"""Bounded, tenant-scoped inventory pages over canonical persisted evidence."""

import base64
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import time

from itsdangerous import BadSignature, TimestampSigner
from sqlalchemy import LargeBinary, String, and_, case, cast, func, literal, or_, select

from src.core.risk_projection import project_agent_risk, project_report_risk
from src.core.stored_risk import MAX_STORED_RISK_BYTES, stored_json_text


MAX_PAGE_LIMIT = 100
MAX_CANDIDATES = 500
MAX_REPORTS = 32
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
RESPONSE_RESERVE_BYTES = 16 * 1024
CURSOR_MAX_AGE_SECONDS = 900
PAGE_TIMEOUT_SECONDS = 5
MAX_CURSOR_BYTES = 4096
ORDERING = 'discovered_at_desc_id_asc'
# Bump when pagination or projection semantics change. The source fingerprint
# also invalidates cursors after any packaged Python source deployment.
INVENTORY_PROJECTION_VERSION = 'inventory-risk-v2'
_RISK_LEVELS = {'critical', 'high', 'medium', 'low', 'minimal', 'unknown'}
_DECIMAL = re.compile(r'[0-9]+\Z')
_GENERATION = re.compile(r'[0-9a-f]{32}\Z')


def _source_policy():
    digest = hashlib.sha256(INVENTORY_PROJECTION_VERSION.encode('ascii'))
    root = Path(__file__).resolve().parents[1]
    for path in sorted(root.rglob('*.py')):
        digest.update(path.relative_to(root).as_posix().encode('utf-8'))
        digest.update(b'\0')
        digest.update(path.read_bytes())
        digest.update(b'\0')
    return digest.hexdigest()


PROJECTION_POLICY = _source_policy()


class InventoryError(ValueError):
    """Only static text crosses the public error boundary."""

    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _invalid_request():
    return InventoryError(400, 'invalid_inventory_request', 'Invalid inventory pagination or filters')


def _invalid_cursor():
    return InventoryError(400, 'invalid_cursor', 'Invalid or expired inventory cursor')


def _stale_cursor():
    return InventoryError(409, 'stale_cursor', 'Inventory changed; restart pagination without a cursor')


def _unavailable():
    return InventoryError(503, 'inventory_projection_unavailable', 'Inventory projection unavailable')


def _signer(secret):
    return TimestampSigner(secret, salt='aiscan-inventory-v1', digest_method=hashlib.sha256)


def _timestamp(value):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 64:
        raise ValueError('Invalid timestamp')
    # Normalize only display parsing for Python 3.10, which requires three or
    # six fractional digits and an explicit UTC offset. The sort key stays raw.
    normalized = re.sub(r'([0-9]{2}:[0-9]{2}:[0-9]{2})[.,]([0-9]+)',
                        lambda match: match[1] + '.' + match[2][:6].ljust(6, '0'), value)
    if normalized.endswith('Z'):
        if not re.search(r'[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]+)?)?Z\Z', normalized):
            raise ValueError('Invalid UTC timestamp')
        normalized = normalized[:-1] + '+00:00'
    return datetime.fromisoformat(normalized)


@dataclass(frozen=True)
class InventoryRequest:
    organization: str
    limit: int
    agent_type: str | None
    risk_level: str | None
    generation: str | None = None
    after: tuple | None = None
    has_cursor: bool = False


def parse_inventory_request(args, organization, secret):
    """Authenticate and bind a continuation before opening any SQL connection."""
    if not isinstance(organization, str) or not 1 <= len(organization) <= 64:
        raise _invalid_request()
    for name in ('limit', 'agent_type', 'risk_level', 'cursor'):
        if len(args.getlist(name)) > 1:
            raise _invalid_request()
    raw_limit = args.get('limit', str(MAX_PAGE_LIMIT))
    if not isinstance(raw_limit, str) or len(raw_limit) > 3 or not _DECIMAL.fullmatch(raw_limit):
        raise _invalid_request()
    limit = int(raw_limit)
    if not 1 <= limit <= MAX_PAGE_LIMIT:
        raise _invalid_request()
    agent_type = args.get('agent_type', '').strip() or None
    risk_level = args.get('risk_level', '').strip().lower() or None
    if (agent_type and (len(agent_type) > 100 or any(ord(mark) < 32 for mark in agent_type))) or (
            risk_level and risk_level not in _RISK_LEVELS):
        raise _invalid_request()
    parsed = InventoryRequest(organization, limit, agent_type, risk_level)
    cursor = args.get('cursor')
    if cursor is None:
        return parsed
    if not isinstance(cursor, str) or not cursor or len(cursor) > MAX_CURSOR_BYTES:
        raise _invalid_cursor()
    try:
        signed = _signer(secret).unsign(cursor, max_age=CURSOR_MAX_AGE_SECONDS)
        raw = base64.b64decode(signed + b'=' * (-len(signed) % 4), altchars=b'-_', validate=True)
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {
                'organization', 'limit', 'agent_type', 'risk_level', 'ordering', 'policy', 'generation', 'after'}:
            raise ValueError('Invalid cursor shape')
        if (value['organization'], value['limit'], value['agent_type'], value['risk_level'], value['ordering']) != (
                organization, limit, agent_type, risk_level, ORDERING) or type(value['limit']) is not int:
            raise ValueError('Invalid cursor binding')
        if not isinstance(value['policy'], str):
            raise ValueError('Invalid policy')
        generation = value['generation']
        if generation is not None and (not isinstance(generation, str) or not _GENERATION.fullmatch(generation)):
            raise ValueError('Invalid generation')
        after = value['after']
        if not isinstance(after, list) or len(after) != 2:
            raise ValueError('Invalid key')
        stamp, identifier = after
        if not isinstance(stamp, str) or not isinstance(identifier, str) or not 1 <= len(identifier) <= 64:
            raise ValueError('Invalid key')
        _timestamp(stamp)
    except (BadSignature, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise _invalid_cursor() from None
    if value['policy'] != PROJECTION_POLICY:
        raise _stale_cursor()
    return InventoryRequest(organization, limit, agent_type, risk_level, generation, (stamp, identifier), True)


def _cursor(parsed, generation, after, secret):
    payload = {'organization': parsed.organization, 'limit': parsed.limit, 'agent_type': parsed.agent_type,
               'risk_level': parsed.risk_level, 'ordering': ORDERING, 'policy': PROJECTION_POLICY,
               'generation': generation, 'after': [after[0], after[1]]}
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False,
                     ensure_ascii=False).encode('utf-8')
    cursor = _signer(secret).sign(base64.urlsafe_b64encode(raw).rstrip(b'=')).decode('ascii')
    if len(cursor) > MAX_CURSOR_BYTES:
        raise _unavailable()
    return cursor


def _check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise _unavailable()


@contextmanager
def _query_deadline(session, deadline):
    """Own this read connection's SQLite handler and clear it even on failure.

    These application-owned read connections have no preexisting progress handler.
    SQLite has no getter for restoring arbitrary third-party handlers.
    """
    connection = session.connection()
    raw = connection.connection.driver_connection if connection.dialect.name == 'sqlite' else None
    if raw is not None:
        raw.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    try:
        yield
    finally:
        if raw is not None:
            raw.set_progress_handler(None, 0)


def _raw_source(session, column, predicate, *, allowance=MAX_STORED_RISK_BYTES):
    """Bound bytes in SQL before fetching text or invoking JSON deserializers."""
    binary = cast(column, LargeBinary)
    size = func.length(binary)
    return session.execute(select(size, case(
        (size <= min(allowance, MAX_STORED_RISK_BYTES), binary), else_=None)).where(predicate)).first()


def _decode_source(raw):
    text = stored_json_text(raw)
    if text is None:
        raise _unavailable()
    try:
        return json.loads(text, parse_constant=lambda _: _reject_constant())
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise _unavailable() from None


def _reject_constant():
    raise ValueError('Non-JSON numeric constant')


def _bounded_field(column, maximum):
    return case((func.length(cast(column, LargeBinary)) <= maximum, column), else_=None).label(column.name)


def inventory_page(session, parsed, secret, observations, scans, reports, generations):
    """Evaluate a bounded keyset page without consulting scalar risk caches."""
    deadline = time.monotonic() + PAGE_TIMEOUT_SECONDS
    try:
        with _query_deadline(session, deadline):
            generation_row = session.execute(select(_bounded_field(generations.c.generation, 32)).where(
                generations.c.organization_id == parsed.organization)).first()
            generation = generation_row[0] if generation_row else None
            if generation_row and (not isinstance(generation, str) or not _GENERATION.fullmatch(generation)):
                raise _unavailable()
            if parsed.has_cursor and parsed.generation != generation:
                raise _stale_cursor()
            conditions = [scans.c.organization_id == parsed.organization]
            if parsed.agent_type:
                conditions.append(observations.c.agent_type == parsed.agent_type)
            if parsed.after:
                stamp, identifier = parsed.after
                raw_stamp = literal(stamp, type_=String())
                conditions.append(or_(observations.c.discovered_at < raw_stamp, and_(
                    observations.c.discovered_at == raw_stamp, observations.c.id > identifier)))
            candidates = session.execute(select(
                _bounded_field(observations.c.id, 256), _bounded_field(observations.c.scan_id, 256),
                _bounded_field(observations.c.agent_name, 1020), _bounded_field(observations.c.agent_type, 400),
                _bounded_field(observations.c.provider, 400), case((and_(
                    func.typeof(observations.c.discovered_at) == 'text',
                    func.length(cast(observations.c.discovered_at, LargeBinary)) <= 64),
                    cast(observations.c.discovered_at, String())), else_=None).label('stored_timestamp'),
                func.length(cast(observations.c.metadata, LargeBinary)).label('metadata_bytes'),
                observations.c.provider.is_(None).label('provider_is_null'),
            ).join(scans, observations.c.scan_id == scans.c.id).where(*conditions).order_by(
                observations.c.discovered_at.desc(), observations.c.id).limit(MAX_CANDIDATES + 1)).all()
            if candidates and generation is None:
                raise _unavailable()
            projected, cache, evaluated, report_bytes, source_bytes, response_bytes, last = [], {}, 0, 0, 0, 0, None
            for candidate in candidates[:MAX_CANDIDATES]:
                _check_deadline(deadline)
                if (not isinstance(candidate.id, str) or not 1 <= len(candidate.id) <= 64
                        or not isinstance(candidate.scan_id, str) or not 1 <= len(candidate.scan_id) <= 64
                        or candidate.agent_name is None or candidate.agent_type is None
                        or candidate.stored_timestamp is None
                        or (candidate.provider is None and not candidate.provider_is_null)
                        or candidate.metadata_bytes is None or candidate.metadata_bytes > MAX_STORED_RISK_BYTES):
                    raise _unavailable()
                displayed_stamp = _timestamp(candidate.stored_timestamp).isoformat()
                remaining = MAX_SOURCE_BYTES - source_bytes
                if candidate.metadata_bytes > remaining:
                    break
                if candidate.scan_id not in cache:
                    if len(cache) >= MAX_REPORTS:
                        break
                    source = _raw_source(session, reports.c.result, reports.c.scan_id == candidate.scan_id,
                                         allowance=remaining - candidate.metadata_bytes)
                    size = source[0] if source else 0
                    if source and (size is None or size > MAX_STORED_RISK_BYTES):
                        raise _unavailable()
                    if size + candidate.metadata_bytes > remaining:
                        break
                    cache[candidate.scan_id] = project_report_risk(_decode_source(source[1]) if source else None)[1]
                    report_bytes += size
                    source_bytes += size
                source = _raw_source(session, observations.c.metadata, observations.c.id == candidate.id,
                                     allowance=MAX_SOURCE_BYTES - source_bytes)
                if source is None or source[0] is None or source[1] is None:
                    raise _unavailable()
                metadata = _decode_source(source[1])
                source_bytes += source[0]
                metadata = metadata if isinstance(metadata, dict) else {}
                asset_id = metadata.get('asset_id', candidate.id)
                asset_id = asset_id if isinstance(asset_id, str) and asset_id else None
                risk = cache[candidate.scan_id].get(asset_id, project_agent_risk())
                _check_deadline(deadline)
                if parsed.risk_level is None or risk['risk_level'] == parsed.risk_level:
                    item = {'id': candidate.id, 'asset_id': asset_id, 'name': candidate.agent_name,
                            'type': candidate.agent_type, 'provider': candidate.provider, **risk,
                            'discovered_at': displayed_stamp}
                    item_bytes = len(json.dumps(item, ensure_ascii=True, allow_nan=False,
                                                separators=(',', ':')).encode('utf-8')) + 1
                    if item_bytes + RESPONSE_RESERVE_BYTES > MAX_RESPONSE_BYTES:
                        raise _unavailable()
                    if response_bytes + item_bytes + RESPONSE_RESERVE_BYTES > MAX_RESPONSE_BYTES:
                        break
                    response_bytes += item_bytes
                    projected.append(item)
                evaluated += 1
                last = (candidate.stored_timestamp, candidate.id)
                if len(projected) >= parsed.limit:
                    break
            search_complete = evaluated == len(candidates)
            if not search_complete and last is None:
                raise _unavailable()
            return {'agents': projected, 'next_cursor': None if search_complete else _cursor(
                parsed, generation, last, secret), 'coverage': {
                    'search_complete': search_complete, 'evaluated_candidates': evaluated,
                    'projected_reports': len(cache), 'projected_report_bytes': report_bytes,
                    'interpreted_source_bytes': source_bytes,
                    'page_limit': parsed.limit, 'window_limit': parsed.limit,
                    'window_truncated': not search_complete,
                    'risk_level_filter_scope': 'tenant_type_assets_cursor_pages',
                    'warning': None if search_complete else 'Inventory search continues on the next cursor page.',
                }}
    except InventoryError:
        raise
    except Exception:
        # SQL, JSON and canonical projection failures share a static boundary.
        raise _unavailable() from None
