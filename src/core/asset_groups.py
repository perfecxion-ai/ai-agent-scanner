"""Restartable derived target groups and bounded, source-backed public readers."""

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import re
import time
import uuid

from itsdangerous import BadSignature, TimestampSigner
from sqlalchemy import LargeBinary, String, and_, case, cast, delete, func, insert, or_, select, true, update
from sqlalchemy.exc import OperationalError

from src.core.asset_group_projection import (
    MAX_ROWS, PageBudget, SourceReader, bounded_field, check_deadline, observation_columns,
    public_text, unavailable,
)
from src.core.inventory import InventoryError, PROJECTION_POLICY


ASSET_GROUP_POLICY = hashlib.sha256(('public-target-groups-v1:' + PROJECTION_POLICY).encode()).hexdigest()
BACKGROUND_SECONDS = 0.5
READ_SECONDS = 5.0
BUSY_TIMEOUT_MS = 50
MAX_PAGE_LIMIT = 100
MAX_RESPONSE_BYTES = 1024 * 1024
RESPONSE_RESERVE = 16384
MAX_CURSOR_BYTES = 4096
CURSOR_SECONDS = 900
GROUP_ORDER = 'observed_at_us_desc_group_id_asc'
HISTORY_ORDER = 'observed_at_us_desc_observation_id_asc_finding_ordinal_asc'
_HEX32 = re.compile(r'[0-9a-f]{32}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_DECIMAL = re.compile(r'[0-9]+\Z')


@dataclass(frozen=True)
class Progress:
    state: str = 'idle'
    organization_id: str | None = None
    processed_rows: int = 0
    cleaned_rows: int = 0
    published: bool = False
    started: bool = False

    @property
    def did_work(self):
        return bool(self.processed_rows or self.cleaned_rows or self.published or self.started)


@dataclass(frozen=True)
class GroupRequest:
    organization: str
    limit: int
    group_id: str | None = None
    build_id: str | None = None
    generation: str | None = None
    nonce: str | None = None
    after: tuple | None = None
    has_cursor: bool = False
    after_complete: bool = False


def _invalid_request():
    return InventoryError(400, 'invalid_asset_group_request', 'Invalid asset group pagination or filters')


def _invalid_cursor():
    return InventoryError(400, 'invalid_cursor', 'Invalid or expired asset group cursor')


def _stale_cursor():
    return InventoryError(409, 'stale_cursor', 'Asset group index changed; restart pagination without a cursor')


def _not_found():
    return InventoryError(404, 'asset_group_not_found', 'Asset group not found')


def _hex(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _int(value, minimum=0):
    return type(value) is int and value >= minimum


def _signer(secret):
    return TimestampSigner(secret, salt='aiscan-asset-groups-v1', digest_method=hashlib.sha256)


def _parse(args, organization, secret, group_id=None):
    try:
        if public_text(organization, 64, identifier=True) != organization:
            raise _invalid_request()
        if group_id is not None and not _hex(group_id, _HEX64):
            raise _invalid_request()
        allowed = {'limit', 'cursor'}
        if set(args) - allowed:
            raise _invalid_request()
        for name in allowed:
            if hasattr(args, 'getlist') and len(args.getlist(name)) > 1:
                raise _invalid_request()
        raw_limit = args.get('limit', '100')
        if not isinstance(raw_limit, str) or len(raw_limit) > 3 or not _DECIMAL.fullmatch(raw_limit):
            raise _invalid_request()
        limit = int(raw_limit)
        if not 1 <= limit <= MAX_PAGE_LIMIT:
            raise _invalid_request()
    except InventoryError as exc:
        if exc.status == 400:
            raise
        raise _invalid_request() from None
    parsed = GroupRequest(organization, limit, group_id)
    if 'cursor' not in args:
        return parsed
    cursor = args.get('cursor')
    if not isinstance(cursor, str) or not cursor or len(cursor) > MAX_CURSOR_BYTES:
        raise _invalid_cursor()
    route, order = ('groups', GROUP_ORDER) if group_id is None else ('history', HISTORY_ORDER)
    try:
        signed = _signer(secret).unsign(cursor, max_age=CURSOR_SECONDS)
        raw = base64.b64decode(signed + b'=' * (-len(signed) % 4), altchars=b'-_', validate=True)
        value = json.loads(raw)
        if type(value) is not dict or set(value) != {
                'organization', 'limit', 'group_id', 'route', 'order', 'policy',
                'build_id', 'generation', 'nonce', 'after', 'after_complete'}:
            raise ValueError('Invalid cursor shape')
        expected = (organization, limit, group_id, route, order)
        if tuple(value[key] for key in ('organization', 'limit', 'group_id', 'route', 'order')) != expected:
            raise ValueError('Invalid cursor scope')
        if type(value['limit']) is not int or not all(_hex(value[key], _HEX32) for key in (
                'build_id', 'generation', 'nonce')) or not _hex(value['policy'], _HEX64):
            raise ValueError('Invalid cursor identity')
        if type(value['after_complete']) is not bool or group_id is None and not value['after_complete']:
            raise ValueError('Invalid cursor boundary')
        after = value['after']
        if type(after) is not list or len(after) != (2 if group_id is None else 3) or type(after[0]) is not int:
            raise ValueError('Invalid cursor key')
        if not -62135596800000000 <= after[0] <= 253402300799999999:
            raise ValueError('Invalid cursor timestamp')
        if group_id is None:
            if not _hex(after[1], _HEX64):
                raise ValueError('Invalid group key')
        elif (public_text(after[1], 64, identifier=True) != after[1]
              or not _int(after[2]) or after[2] > 8 * 1024 * 1024):
            raise ValueError('Invalid finding key')
    except (BadSignature, ValueError, TypeError, KeyError, UnicodeError, RecursionError, InventoryError):
        raise _invalid_cursor() from None
    if value['policy'] != ASSET_GROUP_POLICY:
        raise _stale_cursor()
    return GroupRequest(organization, limit, group_id, value['build_id'],
                        value['generation'], value['nonce'], tuple(after), True, value['after_complete'])


def parse_group_request(args, organization, secret):
    return _parse(args, organization, secret)


def parse_group_history_request(args, organization, group_id, secret):
    return _parse(args, organization, secret, group_id)


def _cursor(parsed, publication, after, secret, *, after_complete=True):
    history = parsed.group_id is not None
    payload = {'organization': parsed.organization, 'limit': parsed.limit,
               'group_id': parsed.group_id, 'route': 'history' if history else 'groups',
               'order': HISTORY_ORDER if history else GROUP_ORDER, 'policy': ASSET_GROUP_POLICY,
               'build_id': publication['active_build_id'], 'generation': publication['active_generation'],
               'nonce': publication['active_nonce'], 'after': list(after), 'after_complete': after_complete}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    result = _signer(secret).sign(base64.urlsafe_b64encode(raw).rstrip(b'=')).decode('ascii')
    if len(result) > MAX_CURSOR_BYTES:
        raise unavailable()
    return result


@contextmanager
def _database_deadline(connection, deadline, stop_event=None):
    # These private application checkouts have no third-party progress handler.
    raw = connection.connection.driver_connection if connection.dialect.name == 'sqlite' else None
    previous = None
    if raw is not None:
        cursor = raw.execute('PRAGMA busy_timeout')
        try:
            previous = cursor.fetchone()[0]
        finally:
            cursor.close()
        raw.execute('PRAGMA busy_timeout=' + str(BUSY_TIMEOUT_MS)).close()
        raw.set_progress_handler(lambda: int(time.monotonic() >= deadline
            or stop_event is not None and stop_event.is_set()), 1000)
    try:
        yield
    finally:
        if raw is not None:
            raw.set_progress_handler(None, 0)
            raw.execute('PRAGMA busy_timeout=' + str(previous)).close()


def _source_count(connection, organization, tables):
    observations, scans = tables['observations'], tables['scans']
    return connection.execute(select(func.count()).select_from(observations.join(
        scans, observations.c.scan_id == scans.c.id)).where(scans.c.organization_id == organization)).scalar_one()


def _generation(connection, organization, tables):
    c = tables['generations'].c
    row = connection.execute(select(bounded_field(c.generation, 32)).where(c.organization_id == organization)).first()
    if row is None:
        return None
    if not _hex(row[0], _HEX32):
        raise unavailable()
    return row[0]


def _publication_row(connection, organization, tables):
    table = tables['publication']
    columns = [bounded_field(column, column.type.length * 4) if isinstance(column.type, String)
        else case((func.typeof(column) == 'integer', column), else_=None).label(column.name)
        for column in table.c]
    row = connection.execute(select(*columns).where(table.c.organization_id == organization)).mappings().first()
    return dict(row) if row is not None else None


def _proof_conditions(c, organization, build, generation, nonce):
    return (c.organization_id == organization, c.build_id == build, c.publication_nonce == nonce,
            c.source_generation == generation, c.projection_policy == ASSET_GROUP_POLICY)


def _ready(connection, organization, tables, publication=None):
    generation = _generation(connection, organization, tables)
    total = _source_count(connection, organization, tables)
    publication = publication if publication is not None else _publication_row(connection, organization, tables)
    if generation is None and total == 0 and publication is None:
        return {'active_row_count': 0, 'active_group_count': 0, 'active_build_id': None,
                'active_generation': None, 'active_nonce': None, 'active_policy': ASSET_GROUP_POLICY}
    if (publication is None or publication['active_generation'] != generation
            or publication['active_policy'] != ASSET_GROUP_POLICY
            or not all(_hex(publication[key], _HEX32) for key in ('active_build_id', 'active_nonce'))
            or not _int(publication['active_row_count']) or not _int(publication['active_group_count'])):
        return None
    c = tables['index'].c
    scope = (c.organization_id == organization, c.build_id == publication['active_build_id'])
    counts = connection.execute(select(func.count()).where(*scope)).scalar_one()
    sealed = connection.execute(select(func.count()).where(*_proof_conditions(
        c, organization, publication['active_build_id'], generation, publication['active_nonce']))).scalar_one()
    heads = connection.execute(select(func.count()).where(*scope, c.is_latest == true())).scalar_one()
    if counts == sealed == publication['active_row_count'] == total and heads == publication['active_group_count']:
        return publication
    return None


class AssetGroupProjector:
    """Only the exclusive dispatcher's idle hook calls this resumable writer."""

    def __init__(self, engine, tables):
        self.engine, self.tables = engine, tables
        self._after_organization, self._next_poll = None, 0.0

    def _cleanup(self, connection, organization, keep):
        table = self.tables['index']
        condition = table.c.organization_id == organization
        if keep:
            condition = and_(condition, table.c.build_id.not_in(keep))
        keys = connection.execute(select(table.c.build_id, table.c.observation_id).where(condition)
                                  .order_by(table.c.build_id, table.c.observation_id).limit(MAX_ROWS)).all()
        for build, observation in keys:
            connection.execute(delete(table).where(table.c.organization_id == organization,
                table.c.build_id == build, table.c.observation_id == observation))
        return len(keys)

    def _stage(self, connection, organization, publication, deadline, stop_event):
        tables, build, generation = self.tables, publication['building_build_id'], publication['building_generation']
        table, observations, scans = tables['index'], tables['observations'], tables['scans']
        c = table.c
        condition = [scans.c.organization_id == organization]
        if publication['after_scan_id'] is not None:
            condition.append(or_(observations.c.scan_id > publication['after_scan_id'], and_(
                observations.c.scan_id == publication['after_scan_id'],
                observations.c.id > publication['after_observation_id'])))
        rows = connection.execute(select(*observation_columns(observations)).join(
            scans, observations.c.scan_id == scans.c.id).where(*condition)
            .order_by(observations.c.scan_id, observations.c.id).limit(MAX_ROWS + 1)).all()
        reader = SourceReader(connection, tables, deadline, stop_event)
        processed, last = 0, None
        for row in rows[:MAX_ROWS]:
            try:
                projected = reader.observation(row, organization)
            except PageBudget:
                break
            head = connection.execute(select(table).where(c.organization_id == organization,
                c.build_id == build, c.group_id == projected.identity.group_id, c.is_latest == true())).mappings().first()
            count = 1 + (head['group_observation_count'] if head else 0)
            complete = projected.history_complete and (head['group_history_complete'] if head else True)
            supported = projected.supported_count
            archived = projected.archived_count
            if head:
                supported = supported + head['group_supported_confirmation_count'] if complete else None
                archived = archived + head['group_archived_claim_count'] if complete else None
            newest = head is None or (projected.observed_at_us > head['observed_at_us'] or
                projected.observed_at_us == head['observed_at_us'] and row.id < head['observation_id'])
            if head:
                values = {'group_observation_count': count, 'group_history_complete': complete,
                          'group_supported_confirmation_count': supported, 'group_archived_claim_count': archived}
                if newest:
                    values['is_latest'] = False
                connection.execute(update(table).where(c.organization_id == organization, c.build_id == build,
                    c.observation_id == head['observation_id']).values(**values))
            values = {'organization_id': organization, 'build_id': build, 'observation_id': row.id,
                'scan_id': row.scan_id, 'report_asset_id': projected.asset_id, 'group_id': projected.identity.group_id,
                'identity_status': projected.identity.status, 'unmerged_reason': projected.identity.reason,
                'target': projected.identity.target, 'observed_at_us': projected.observed_at_us,
                'agent_type': row.agent_type, 'is_latest': newest, 'history_complete': projected.history_complete,
                'group_history_complete': complete, 'supported_confirmation_count': projected.supported_count,
                'archived_claim_count': projected.archived_count, 'group_observation_count': count if newest else 0,
                'group_supported_confirmation_count': supported if newest else None,
                'group_archived_claim_count': archived if newest else None, 'publication_nonce': None,
                'source_generation': generation, 'projection_policy': ASSET_GROUP_POLICY}
            connection.execute(insert(table).values(**values))
            processed += 1
            last = row
        if last is not None:
            connection.execute(update(tables['publication']).where(
                tables['publication'].c.organization_id == organization).values(
                after_scan_id=last.scan_id, after_observation_id=last.id,
                processed_count=publication['processed_count'] + processed))
        return processed, len(rows) == processed

    def _seal(self, connection, organization, publication):
        table, pubs = self.tables['index'], self.tables['publication']
        c, build, generation = table.c, publication['building_build_id'], publication['building_generation']
        scope = (c.organization_id == organization, c.build_id == build)
        total = connection.execute(select(func.count()).where(*scope)).scalar_one()
        source_count = _source_count(connection, organization, self.tables)
        if total != publication['processed_count'] or total != source_count:
            raise unavailable()
        nonces = connection.execute(select(c.publication_nonce).where(*scope,
            c.publication_nonce.is_not(None)).distinct().limit(2)).scalars().all()
        if len(nonces) > 1 or nonces and not _hex(nonces[0], _HEX32):
            raise unavailable()
        nonce = nonces[0] if nonces else uuid.uuid4().hex
        unsealed = connection.execute(select(c.observation_id).where(*scope,
            c.publication_nonce.is_(None)).order_by(c.observation_id).limit(MAX_ROWS)).scalars().all()
        if unsealed:
            connection.execute(update(table).where(*scope, c.observation_id.in_(unsealed)).values(publication_nonce=nonce))
            return Progress('sealing', organization, processed_rows=0, started=True)
        sealed = connection.execute(select(func.count()).where(*_proof_conditions(
            c, organization, build, generation, nonce))).scalar_one()
        heads = connection.execute(select(func.count(), func.coalesce(func.sum(c.group_observation_count), 0))
            .where(*scope, c.is_latest == true())).first()
        groups = connection.execute(select(func.count(func.distinct(c.group_id))).where(*scope)).scalar_one()
        if sealed != total or heads[0] != groups or heads[1] != total:
            raise unavailable()
        changed = connection.execute(update(pubs).where(pubs.c.organization_id == organization,
            pubs.c.building_build_id == build, pubs.c.building_generation == generation,
            pubs.c.building_policy == ASSET_GROUP_POLICY,
            self.tables['generations'].select().where(
                self.tables['generations'].c.organization_id == organization,
                self.tables['generations'].c.generation == generation).exists()).values(
                active_build_id=build, active_generation=generation, active_policy=ASSET_GROUP_POLICY,
                active_nonce=nonce, active_row_count=total, active_group_count=groups,
                building_build_id=None, building_generation=None, building_policy=None,
                after_scan_id=None, after_observation_id=None, processed_count=0, error_code=None)).rowcount
        if changed != 1:
            raise PageBudget()
        return Progress('published', organization, published=True)

    def _organization(self, connection, organization, deadline, stop_event):
        tables, pub_table = self.tables, self.tables['publication']
        generation = _generation(connection, organization, tables)
        publication = _publication_row(connection, organization, tables)
        if publication is None:
            connection.execute(insert(pub_table).values(organization_id=organization, processed_count=0))
            publication = _publication_row(connection, organization, tables)
        build = publication['building_build_id']
        if build and (publication['building_generation'] != generation
                      or publication['building_policy'] != ASSET_GROUP_POLICY):
            connection.execute(update(pub_table).where(pub_table.c.organization_id == organization).values(
                building_build_id=None, building_generation=None, building_policy=None,
                after_scan_id=None, after_observation_id=None, processed_count=0, error_code=None))
            publication = _publication_row(connection, organization, tables)
            build = None
        if build and publication['error_code']:
            return Progress('blocked', organization)
        ready = _ready(connection, organization, tables, publication)
        if ready is not None and not build:
            cleaned = self._cleanup(connection, organization, [publication['active_build_id']])
            return Progress('building' if cleaned else 'idle', organization, cleaned_rows=cleaned)
        if not build:
            cleaned = self._cleanup(connection, organization, [publication['active_build_id']]
                                    if publication['active_build_id'] else [])
            if cleaned:
                return Progress('building', organization, cleaned_rows=cleaned)
            build = uuid.uuid4().hex
            connection.execute(update(pub_table).where(pub_table.c.organization_id == organization).values(
                building_build_id=build, building_generation=generation, building_policy=ASSET_GROUP_POLICY,
                after_scan_id=None, after_observation_id=None, processed_count=0, error_code=None))
            publication = _publication_row(connection, organization, tables)
        try:
            processed, exhausted = self._stage(connection, organization, publication, deadline, stop_event)
            if processed or not exhausted:
                return Progress('building', organization, processed_rows=processed, started=True)
            publication = _publication_row(connection, organization, tables)
            return self._seal(connection, organization, publication)
        except InventoryError:
            connection.execute(update(pub_table).where(pub_table.c.organization_id == organization).values(
                error_code='source_unavailable'))
            return Progress('blocked', organization)

    def step(self, stop_event=None):
        now = time.monotonic()
        if now < self._next_poll:
            return Progress()
        if stop_event is not None and stop_event.is_set():
            return Progress('cancelled')
        deadline = now + BACKGROUND_SECONDS
        try:
            with self.engine.connect() as connection, _database_deadline(connection, deadline, stop_event):
                connection.exec_driver_sql('BEGIN IMMEDIATE')
                try:
                    g = self.tables['generations'].c
                    statement = select(bounded_field(g.organization_id, 256)).where(
                        func.typeof(g.organization_id) == 'text', func.length(g.organization_id) >= 1,
                        func.length(g.organization_id) <= 64,
                        func.length(cast(g.organization_id, LargeBinary)) <= 256
                    ).order_by(g.organization_id).limit(MAX_ROWS)
                    if self._after_organization is not None:
                        statement = statement.where(g.organization_id > self._after_organization)
                    organizations = connection.execute(statement).scalars().all()
                    blocked = None
                    for organization in organizations:
                        check_deadline(deadline, stop_event)
                        self._after_organization = organization
                        try:
                            if public_text(organization, 64, identifier=True) != organization:
                                continue
                        except InventoryError:
                            continue
                        progress = self._organization(connection, organization, deadline, stop_event)
                        if progress.state == 'blocked':
                            blocked = progress
                            continue
                        if progress.did_work:
                            connection.commit()
                            return progress
                    wrapped = self._after_organization is not None and not organizations
                    self._after_organization = None if len(organizations) < MAX_ROWS else self._after_organization
                    connection.commit()
                    self._next_poll = time.monotonic() + (0 if wrapped else 0.5)
                    return blocked or Progress()
                except BaseException:
                    connection.rollback()
                    raise
        except PageBudget:
            return Progress('cancelled' if stop_event is not None and stop_event.is_set() else 'busy')
        except (OperationalError, InventoryError, ValueError, TypeError, KeyError):
            self._next_poll = time.monotonic() + 0.5
            return Progress('busy')


def _coverage(publication, reader, evaluated, complete, *, history=False):
    result = {'search_complete': complete, 'scope': 'finding_occurrences_and_no_finding_observations'
              if history else 'public_target_groups', 'risk_scope': 'latest_observation',
              'evaluated_candidates': evaluated, 'projected_reports': len(reader.reports),
              'interpreted_source_bytes': reader.source_bytes,
              'indexed_observations': publication['active_row_count'],
              'indexed_groups': publication['active_group_count']}
    return result


def _read_publication(connection, parsed, tables):
    if parsed.has_cursor and parsed.generation != _generation(connection, parsed.organization, tables):
        raise _stale_cursor()
    publication = _ready(connection, parsed.organization, tables)
    if publication is None:
        raise unavailable()
    if parsed.has_cursor and (parsed.build_id, parsed.generation, parsed.nonce) != tuple(
            publication[key] for key in ('active_build_id', 'active_generation', 'active_nonce')):
        raise _stale_cursor()
    return publication


def _reopen(reader, cache, organization):
    row = reader.observation_row(cache.observation_id, cache.scan_id, organization)
    if row is None:
        raise unavailable()
    source = reader.observation(row, organization)
    if (source.identity.group_id != cache.group_id or source.identity.status != cache.identity_status
            or source.observed_at_us != cache.observed_at_us or source.asset_id != cache.report_asset_id):
        raise unavailable()
    return source


def _entry_size(item):
    return len(json.dumps(item, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()) + 1


def _cache_columns(table):
    c = table.c
    return [bounded_field(c.observation_id, 256), bounded_field(c.scan_id, 256),
            bounded_field(c.report_asset_id, 1024), bounded_field(c.group_id, 64),
            bounded_field(c.identity_status, 16), c.observed_at_us,
            c.group_history_complete, c.group_observation_count,
            c.group_supported_confirmation_count, c.group_archived_claim_count]


def group_page(session, parsed, secret, tables):
    deadline = time.monotonic() + READ_SECONDS
    connection = session.connection()
    try:
        with _database_deadline(connection, deadline):
            publication = _read_publication(connection, parsed, tables)
            reader = SourceReader(connection, tables, deadline)
            if not publication['active_row_count']:
                return {'asset_groups': [], 'next_cursor': None,
                        'coverage': _coverage(publication, reader, 0, True)}
            c = tables['index'].c
            conditions = list(_proof_conditions(c, parsed.organization, publication['active_build_id'],
                publication['active_generation'], publication['active_nonce'])) + [c.is_latest.is_(True)]
            if parsed.after:
                conditions.append(or_(c.observed_at_us < parsed.after[0], and_(
                    c.observed_at_us == parsed.after[0], c.group_id > parsed.after[1])))
            rows = connection.execute(select(*_cache_columns(tables['index'])).where(*conditions)
                .order_by(c.observed_at_us.desc(), c.group_id).limit(MAX_ROWS + 1)).all()
            items, response_bytes, evaluated, last = [], 0, 0, None
            for row in rows[:MAX_ROWS]:
                try:
                    source = _reopen(reader, row, parsed.organization)
                except PageBudget:
                    break
                item = {'id': row.group_id, 'identity_status': source.identity.status,
                    'unmerged_reason': source.identity.reason, 'target': source.identity.target,
                    'latest_observation': source.latest(), 'latest_observation_risk': source.risk,
                    'observation_count': row.group_observation_count,
                    'confirmation_history': {'complete': row.group_history_complete,
                        'supported_occurrences': row.group_supported_confirmation_count,
                        'archived_claims': row.group_archived_claim_count,
                        'remediation_status': 'not_evaluated',
                        'url': '/api/asset-groups/' + row.group_id + '/history'}}
                size = _entry_size(item)
                if size + RESPONSE_RESERVE > MAX_RESPONSE_BYTES:
                    raise unavailable()
                if response_bytes + size + RESPONSE_RESERVE > MAX_RESPONSE_BYTES:
                    break
                items.append(item)
                response_bytes += size
                evaluated += 1
                last = (row.observed_at_us, row.group_id)
                if len(items) == parsed.limit:
                    break
            complete = evaluated == len(rows)
            if not complete and last is None:
                raise unavailable()
            return {'asset_groups': items, 'next_cursor': None if complete else _cursor(parsed, publication, last, secret),
                    'coverage': _coverage(publication, reader, evaluated, complete)}
    except InventoryError:
        raise
    except Exception:
        raise unavailable() from None


def group_history_page(session, parsed, secret, tables):
    deadline = time.monotonic() + READ_SECONDS
    connection = session.connection()
    try:
        with _database_deadline(connection, deadline):
            publication = _read_publication(connection, parsed, tables)
            reader = SourceReader(connection, tables, deadline)
            c = tables['index'].c
            scope = list(_proof_conditions(c, parsed.organization, publication['active_build_id'],
                publication['active_generation'], publication['active_nonce'])) + [c.group_id == parsed.group_id]
            if not connection.execute(select(c.observation_id).where(*scope).limit(1)).first():
                raise _not_found()
            conditions = list(scope)
            if parsed.after:
                conditions.append(or_(c.observed_at_us < parsed.after[0], and_(
                    c.observed_at_us == parsed.after[0], c.observation_id > parsed.after[1]
                    if parsed.after_complete else c.observation_id >= parsed.after[1])))
            rows = connection.execute(select(*_cache_columns(tables['index'])).where(*conditions)
                .order_by(c.observed_at_us.desc(), c.observation_id).limit(MAX_ROWS + 1)).all()
            items, response_bytes, evaluated, last, complete, last_complete = [], 0, 0, None, False, False
            for row in rows[:MAX_ROWS]:
                try:
                    source = _reopen(reader, row, parsed.organization)
                except PageBudget:
                    break
                count = max(1, len(source.claims))
                start = parsed.after[2] + 1 if parsed.after and row.observation_id == parsed.after[1] else 0
                if start >= count:
                    raise _invalid_cursor()
                for ordinal in range(start, count):
                    check_deadline(deadline)
                    item = source.occurrence(ordinal)
                    size = _entry_size(item)
                    if size + RESPONSE_RESERVE > MAX_RESPONSE_BYTES:
                        raise unavailable()
                    if response_bytes + size + RESPONSE_RESERVE > MAX_RESPONSE_BYTES:
                        break
                    items.append(item)
                    response_bytes += size
                    last = (row.observed_at_us, row.observation_id, ordinal)
                    last_complete = ordinal == count - 1
                    if len(items) == parsed.limit:
                        break
                else:
                    evaluated += 1
                    continue
                # The current observation may continue with its next original ordinal.
                if last is not None and last[1] == row.observation_id and last[2] == count - 1:
                    evaluated += 1
                break
            else:
                complete = len(rows) <= MAX_ROWS
            if evaluated == len(rows):
                complete = True
            if not complete and last is None:
                raise unavailable()
            return {'group_id': parsed.group_id, 'history': items,
                    'next_cursor': None if complete else _cursor(
                        parsed, publication, last, secret, after_complete=last_complete),
                    'coverage': _coverage(publication, reader, evaluated, complete, history=True)}
    except InventoryError:
        raise
    except Exception:
        raise unavailable() from None
