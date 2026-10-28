"""Bounded source interpretation shared by group staging and read-only pages."""

from collections import Counter
from dataclasses import dataclass, field
from datetime import timezone
import json
import re
import time

from sqlalchemy import Integer, LargeBinary, String, and_, bindparam, case, cast, func, select

from src.core.asset_identity import GroupIdentity, target_group_identity
from src.core.contracts import (
    CHECK_SCHEMA_VERSION, access_evidence_views_match, confirmed_findings,
    has_evidence_contract, is_supported_evidence_version, tenant_evidence_views_match,
    validate_check_evidence, validate_scan_result,
)
from src.core.inventory import InventoryError, _timestamp
from src.core.redaction import collect_secrets, redact_secrets
from src.core.risk_projection import project_agent_risk, project_report_risk
from src.core.stored_risk import MAX_STORED_RISK_BYTES, stored_json_text


MAX_ROWS = 500
MAX_REPORTS = 32
MAX_SOURCE_BYTES = 16 * 1024 * 1024
_RULE = re.compile(r'[a-z][a-z0-9_.-]{0,127}\Z')
_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}


def unavailable():
    return InventoryError(503, 'asset_group_projection_unavailable', 'Asset group projection unavailable')


class PageBudget(Exception):
    """A successful page or step must stop before consuming its next source."""


def check_deadline(deadline, stop_event=None):
    if stop_event is not None and stop_event.is_set():
        raise PageBudget()
    if time.monotonic() >= deadline:
        raise PageBudget()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate source member')
        result[key] = value
    return result


def _constant(_):
    raise ValueError('Nonfinite source value')


def decode_source(raw):
    if raw is None:
        return None
    text = stored_json_text(raw)
    if text is None:
        raise unavailable()
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise unavailable() from None


def bounded_field(column, maximum):
    return case((func.length(cast(column, LargeBinary)) <= maximum, column), else_=None).label(column.name)


def observation_columns(observations):
    c = observations.c
    fields = [(c.id, 256), (c.scan_id, 256), (c.agent_name, 1020), (c.agent_type, 400),
              (c.provider, 400), (c.model_name, 1020), (c.endpoint_url, 16384)]
    return [*[bounded_field(column, maximum) for column, maximum in fields],
            *[column.is_(None).label(column.name + '_is_null') for column, _ in fields],
            case((and_(func.typeof(c.discovered_at) == 'text',
                       func.length(cast(c.discovered_at, LargeBinary)) <= 64), cast(c.discovered_at, String())),
                 else_=None).label('stored_timestamp'),
            func.length(cast(c.discovered_at, LargeBinary)).label('timestamp_bytes'),
            func.length(cast(c.metadata, LargeBinary)).label('metadata_bytes')]


def public_text(value, maximum, *, nullable=False, identifier=False):
    if value is None and nullable:
        return None
    if (not isinstance(value, str) or not 0 < len(value) <= maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise unavailable()
    cleaned = redact_secrets(value, collect_secrets(value))
    if identifier and (cleaned != value or '[redacted' in value.casefold()):
        return None
    return cleaned


def timestamp_parts(raw):
    try:
        value = _timestamp(raw)
        utc = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        epoch = utc.replace(year=1970, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        delta = utc - epoch
        micros = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
        return micros, value.isoformat()
    except (TypeError, ValueError, OverflowError):
        raise unavailable() from None


def _supported_source(report, agent):
    """Receipt support does not require the asynchronous scorer to have run."""
    try:
        if not isinstance(report, dict) or report.get('check_schema_version') != CHECK_SCHEMA_VERSION:
            return False, set()
        validate_scan_result(report, validate_evidence=False)
        root_version = report.get('check_evidence_schema_version')
        if 'check_evidence_schema_version' in report:
            if not is_supported_evidence_version(root_version) or agent.get('check_evidence_schema_version') != root_version:
                return False, set()
        elif has_evidence_contract(agent):
            return False, set()
        sources = [value for value in report.get('security_results', [])
                   if isinstance(value, dict) and value.get('agent_id') == agent['id']]
        if len(sources) != 1:
            return False, set()
        source = sources[0]
        if source.get('status') != agent.get('security_status') or source.get('status') not in {
                'completed', 'partial', 'failed'}:
            return False, set()
        shared = ('check_evidence_schema_version', 'check_evidence_run_id', 'provider', 'model')
        if any((key in source) != (key in agent) or source.get(key) != agent.get(key) for key in shared):
            return False, set()
        if any(source.get(key, []) != agent.get(key, []) for key in (
                'checks', 'vulnerabilities', 'observations', 'check_evidence')):
            return False, set()
        if not tenant_evidence_views_match(agent, source) or not access_evidence_views_match(agent, source):
            return False, set()
        execution = dict(agent, status=source['status'], check_schema_version=CHECK_SCHEMA_VERSION)
        validate_check_evidence(execution)
        supported = {id(value) for value in confirmed_findings(execution)}
        # The dictionaries in execution are the original agent's occurrences.
        return True, supported
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError, OverflowError):
        return False, set()


@dataclass
class ReportSource:
    report: object
    agents: dict
    risks: dict
    _support: dict[str, tuple[bool, frozenset[int]]] = field(default_factory=dict, repr=False)

    def support(self, alias):
        # This decoded source belongs to one reader and is never mutated. Row
        # selectors must still match before reusing its immutable evidence facts.
        if alias not in self._support:
            agent = self.agents[alias]
            claims = agent.get('vulnerabilities', [])
            shape = isinstance(claims, list) and all(isinstance(value, dict) for value in claims)
            valid, supported = _supported_source(self.report, agent)
            ordinals = frozenset(ordinal for ordinal, claim in enumerate(claims)
                                if id(claim) in supported) if shape else frozenset()
            self._support[alias] = (bool(valid and shape), ordinals)
        return self._support[alias]

    @classmethod
    def from_value(cls, report):
        agents = {}
        if isinstance(report, dict) and report.get('schema_version') == '1.0' and isinstance(report.get('agents'), list):
            identifiers = Counter(value.get('id') for value in report['agents']
                                  if isinstance(value, dict) and isinstance(value.get('id'), str))
            agents = {value['id']: value for value in report['agents']
                      if isinstance(value, dict) and isinstance(value.get('id'), str)
                      and identifiers[value['id']] == 1}
        try:
            risks = project_report_risk(report)[1]
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
            risks = {}
        return cls(report, agents, risks)


@dataclass
class ObservationSource:
    row: object
    identity: GroupIdentity
    asset_id: str | None
    agent: dict | None
    risk: dict
    claims: list
    supported: frozenset
    history_complete: bool
    observed_at_us: int
    discovered_at: str

    @property
    def supported_count(self):
        return len(self.supported) if self.history_complete else None

    @property
    def archived_count(self):
        return len(self.claims) - len(self.supported) if self.history_complete else None

    def latest(self):
        return {'id': self.row.id, 'asset_id': self.asset_id, 'scan_id': self.row.scan_id,
                'name': public_text(self.row.agent_name, 255), 'type': public_text(self.row.agent_type, 100),
                'provider': public_text(self.row.provider, 100, nullable=True),
                'discovered_at': self.discovered_at, 'security_status': self.risk['security_status']}

    def occurrence(self, ordinal):
        item = {'observation_id': self.row.id, 'asset_id': self.asset_id, 'scan_id': self.row.scan_id,
                'discovered_at': self.discovered_at, 'finding_ordinal': ordinal,
                'remediation_status': 'not_evaluated'}
        if not self.claims:
            if ordinal != 0:
                raise unavailable()
            return {**item, 'finding_id': None, 'classification': 'observation',
                    'severity': None, 'rule_id': None, 'observation_risk': self.risk}
        claim = self.claims[ordinal]
        identifier = claim.get('id')
        try:
            identifier = public_text(identifier, 256, nullable=True, identifier=True)
        except InventoryError:
            identifier = None
        rule = claim.get('rule_id')
        rule = rule if isinstance(rule, str) and _RULE.fullmatch(rule) else None
        severity = claim.get('severity')
        return {**item, 'finding_id': identifier,
                'classification': 'supported_confirmation' if ordinal in self.supported else 'archived_claim',
                'severity': severity if isinstance(severity, str) and severity in _SEVERITIES else 'unknown',
                'rule_id': rule}


class SourceReader:
    def __init__(self, connection, tables, deadline, stop_event=None):
        self.connection, self.tables, self.deadline, self.stop_event = connection, tables, deadline, stop_event
        self.reports, self.source_bytes = {}, 0
        self._observation_statement = None
        self._raw_statements = {}

    def observation_row(self, observation_id, scan_id, organization):
        check_deadline(self.deadline, self.stop_event)
        if self._observation_statement is None:
            observations, scans = self.tables['observations'], self.tables['scans']
            self._observation_statement = select(*observation_columns(observations)).join(
                scans, observations.c.scan_id == scans.c.id).where(
                observations.c.id == bindparam('group_observation_id'),
                observations.c.scan_id == bindparam('group_scan_id'),
                scans.c.organization_id == bindparam('group_organization_id'))
        return self.connection.execute(self._observation_statement, {
            'group_observation_id': observation_id, 'group_scan_id': scan_id,
            'group_organization_id': organization}).first()

    def _raw(self, column, selector_column, identifier, allowance):
        check_deadline(self.deadline, self.stop_event)
        key = (column, selector_column)
        if key not in self._raw_statements:
            binary = cast(column, LargeBinary)
            size = func.length(binary)
            self._raw_statements[key] = select(size, case(
                (size <= bindparam('group_source_allowance', type_=Integer), binary), else_=None),
                column.is_(None)).where(selector_column == bindparam('group_source_identifier'))
        record = self.connection.execute(self._raw_statements[key], {
            'group_source_identifier': identifier,
            'group_source_allowance': min(allowance, MAX_STORED_RISK_BYTES)}).first()
        if record is None:
            return False, None, 0
        length, raw, is_null = record
        if is_null:
            return True, None, 0
        if length is None or length > MAX_STORED_RISK_BYTES:
            raise unavailable()
        if length > allowance:
            raise PageBudget()
        if raw is None:
            raise unavailable()
        return True, raw, length

    def observation(self, row, organization):
        check_deadline(self.deadline, self.stop_event)
        for name, maximum, nullable in (('id', 64, False), ('scan_id', 64, False),
                ('agent_name', 255, False), ('agent_type', 100, False), ('provider', 100, True),
                ('model_name', 255, True), ('endpoint_url', 4096, True)):
            value = getattr(row, name)
            if value is None and not getattr(row, name + '_is_null'):
                raise unavailable()
            if name in {'id', 'scan_id'}:
                if public_text(value, maximum, identifier=True) is None:
                    raise unavailable()
            elif value is not None:
                public_text(value, maximum)
            elif not nullable:
                raise unavailable()
        if row.timestamp_bytes is None or row.timestamp_bytes > 64 or row.stored_timestamp is None:
            raise unavailable()
        micros, displayed = timestamp_parts(row.stored_timestamp)
        metadata_size = row.metadata_bytes or 0
        if metadata_size > MAX_STORED_RISK_BYTES:
            raise unavailable()
        remaining = MAX_SOURCE_BYTES - self.source_bytes
        if metadata_size > remaining:
            raise PageBudget()
        if row.scan_id not in self.reports:
            if len(self.reports) >= MAX_REPORTS:
                raise PageBudget()
            report_table = self.tables['reports']
            _, raw, size = self._raw(report_table.c.result, report_table.c.scan_id, row.scan_id,
                                     remaining - metadata_size)
            self.reports[row.scan_id] = ReportSource.from_value(decode_source(raw))
            self.source_bytes += size
        observations = self.tables['observations']
        exists, raw, size = self._raw(observations.c.metadata, observations.c.id, row.id,
                                      MAX_SOURCE_BYTES - self.source_bytes)
        if not exists:
            raise unavailable()
        metadata = decode_source(raw)
        self.source_bytes += size
        metadata = metadata if isinstance(metadata, dict) else {}
        alias = metadata.get('asset_id', row.id)
        alias = alias if isinstance(alias, str) and alias else None
        try:
            alias = public_text(alias, 256, nullable=True, identifier=True)
        except InventoryError:
            alias = None
        source = self.reports[row.scan_id]
        agent = source.agents.get(alias)
        singleton = target_group_identity({}, organization_id=organization, observation_id=row.id)
        unknown = project_agent_risk()
        if agent is None:
            return ObservationSource(row, GroupIdentity(singleton.group_id, 'unmerged', 'unmatched_asset_alias', None),
                                     alias, None, unknown, [], frozenset(), False, micros, displayed)
        # Public snapshot selectors must actually refer to this archived target.
        selected = {'endpoint': row.endpoint_url, 'provider': row.provider, 'model': row.model_name,
                    'evidence_context_id': agent.get('evidence_context_id'), 'metadata': metadata}
        original = target_group_identity(agent, organization_id=organization, observation_id=row.id)
        snapshot = target_group_identity(selected, organization_id=organization, observation_id=row.id)
        same_http_endpoint = (original.status == snapshot.status == 'grouped'
            and original.target.get('kind') == snapshot.target.get('kind') == 'http_target'
            and original.target.get('endpoint') == snapshot.target.get('endpoint'))
        exact = (row.provider == agent.get('provider') and row.model_name == agent.get('model')
                 and (row.endpoint_url == agent.get('endpoint') or same_http_endpoint))
        if not exact:
            return ObservationSource(row, GroupIdentity(singleton.group_id, 'unmerged',
                                     'snapshot_target_mismatch', None), alias, None, unknown,
                                     [], frozenset(), False, micros, displayed)
        if (original.status != 'grouped' or snapshot.status != 'grouped' or original.target != snapshot.target):
            identity = GroupIdentity(singleton.group_id, 'unmerged',
                                     original.reason or snapshot.reason or 'snapshot_target_mismatch', None)
        else:
            identity = original
        claims = agent.get('vulnerabilities', [])
        claim_shape = isinstance(claims, list) and all(isinstance(value, dict) for value in claims)
        claims = claims if claim_shape else []
        complete, supported = source.support(alias)
        risk = source.risks.get(alias, unknown)
        return ObservationSource(row, identity, alias, agent, risk, claims, supported, complete, micros, displayed)
