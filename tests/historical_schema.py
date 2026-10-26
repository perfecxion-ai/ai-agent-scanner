"""Frozen historical SQLite fixtures, independent of current ORM metadata."""

from datetime import datetime

from sqlalchemy import Boolean, Column, DDL, DateTime, Float, Index, Integer, JSON, MetaData, String, Table, Text, event


BASE_TABLES = frozenset({'scan_session', 'discovered_agent'})
VERSION_ONE_TABLES = BASE_TABLES | {'scan_result', 'scan_job', 'schema_version', 'audit_event'}
VERSION_TWO_TABLES = VERSION_ONE_TABLES | {'scan_template'}
VERSION_THREE_TABLES = VERSION_TWO_TABLES | {'scan_schedule', 'scan_occurrence'}
VERSION_FOUR_TABLES = VERSION_THREE_TABLES
VERSION_FIVE_TABLES = VERSION_FOUR_TABLES | {'inventory_generation'}
LAYOUTS = {0: BASE_TABLES, 1: VERSION_ONE_TABLES, 2: VERSION_TWO_TABLES, 3: VERSION_THREE_TABLES,
           4: VERSION_FOUR_TABLES, 5: VERSION_FIVE_TABLES}

# Exact schema 5 SQL captured at 6af7fa2, independent of current registrations.
SCHEMA_FIVE_TRIGGERS = {
    'aiscan_inventory_observation_insert': 'CREATE TRIGGER aiscan_inventory_observation_insert AFTER INSERT ON discovered_agent  BEGIN INSERT INTO inventory_generation (organization_id, generation) SELECT organization_id, lower(hex(randomblob(16))) FROM scan_session WHERE id = NEW.scan_id ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation; END',
    'aiscan_inventory_observation_update': 'CREATE TRIGGER aiscan_inventory_observation_update AFTER UPDATE ON discovered_agent  BEGIN INSERT INTO inventory_generation (organization_id, generation) SELECT organization_id, lower(hex(randomblob(16))) FROM scan_session WHERE id = OLD.scan_id ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation;INSERT INTO inventory_generation (organization_id, generation) SELECT organization_id, lower(hex(randomblob(16))) FROM scan_session WHERE id = NEW.scan_id ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation; END',
    'aiscan_inventory_observation_delete': 'CREATE TRIGGER aiscan_inventory_observation_delete AFTER DELETE ON discovered_agent  BEGIN INSERT INTO inventory_generation (organization_id, generation) SELECT organization_id, lower(hex(randomblob(16))) FROM scan_session WHERE id = OLD.scan_id ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation; END',
    'aiscan_inventory_report_insert': 'CREATE TRIGGER aiscan_inventory_report_insert AFTER INSERT ON scan_result  BEGIN INSERT INTO inventory_generation (organization_id, generation) SELECT organization_id, lower(hex(randomblob(16))) FROM scan_session WHERE id = NEW.scan_id ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation; END',
    'aiscan_inventory_report_update': 'CREATE TRIGGER aiscan_inventory_report_update AFTER UPDATE ON scan_result  BEGIN INSERT INTO inventory_generation (organization_id, generation) SELECT organization_id, lower(hex(randomblob(16))) FROM scan_session WHERE id = OLD.scan_id ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation;INSERT INTO inventory_generation (organization_id, generation) SELECT organization_id, lower(hex(randomblob(16))) FROM scan_session WHERE id = NEW.scan_id ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation; END',
    'aiscan_inventory_report_delete': 'CREATE TRIGGER aiscan_inventory_report_delete AFTER DELETE ON scan_result  BEGIN INSERT INTO inventory_generation (organization_id, generation) SELECT organization_id, lower(hex(randomblob(16))) FROM scan_session WHERE id = OLD.scan_id ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation; END',
    'aiscan_inventory_session_insert': 'CREATE TRIGGER aiscan_inventory_session_insert AFTER INSERT ON scan_session WHEN EXISTS (SELECT 1 FROM discovered_agent WHERE scan_id = NEW.id) BEGIN INSERT INTO inventory_generation (organization_id, generation) VALUES (NEW.organization_id, lower(hex(randomblob(16)))) ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation; END',
    'aiscan_inventory_session_delete': 'CREATE TRIGGER aiscan_inventory_session_delete AFTER DELETE ON scan_session WHEN EXISTS (SELECT 1 FROM discovered_agent WHERE scan_id = OLD.id) BEGIN INSERT INTO inventory_generation (organization_id, generation) VALUES (OLD.organization_id, lower(hex(randomblob(16)))) ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation; END',
    'aiscan_inventory_session_update': 'CREATE TRIGGER aiscan_inventory_session_update AFTER UPDATE OF id, organization_id ON scan_session WHEN OLD.id IS NOT NEW.id OR OLD.organization_id IS NOT NEW.organization_id BEGIN INSERT INTO inventory_generation (organization_id, generation) VALUES (OLD.organization_id, lower(hex(randomblob(16)))) ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation;INSERT INTO inventory_generation (organization_id, generation) VALUES (NEW.organization_id, lower(hex(randomblob(16)))) ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation; END',
}


def _time():
    return datetime(2026, 1, 1)


def historical_metadata(names=None, *, version=3):
    """Build fixed old definitions; Python defaults only simplify fixture inserts."""
    if version not in LAYOUTS:
        raise ValueError('Unsupported historical fixture version')
    selected = LAYOUTS[version] if names is None else frozenset(names)
    if not selected <= VERSION_FIVE_TABLES:
        raise ValueError('Unsupported historical fixture tables')
    metadata = MetaData()
    Table('scan_session', metadata,
          Column('id', String(64), primary_key=True),
          Column('organization_id', String(64), nullable=False),
          Column('scan_name', String(255), nullable=False),
          Column('scan_type', String(50), nullable=False),
          Column('status', String(50), nullable=False, default='pending'),
          Column('progress', Float, nullable=False, default=0.0),
          Column('target_scope', JSON, nullable=False),
          Column('scan_config', JSON, nullable=False),
          Column('agents_discovered', Integer, nullable=False, default=0),
          Column('vulnerabilities_found', Integer, nullable=False, default=0),
          Column('critical_risks', Integer, nullable=False, default=0),
          Column('overall_risk_score', Float, nullable=version >= 4,
                 default=None if version >= 4 else 0.0),
          Column('created_at', DateTime, nullable=False, default=_time),
          Column('started_at', DateTime, nullable=True),
          Column('completed_at', DateTime, nullable=True),
          Column('created_by', String(255), nullable=True),
          Column('user_ip', String(45), nullable=True))
    Table('discovered_agent', metadata,
          Column('id', String(64), primary_key=True),
          Column('scan_id', String(64), nullable=False),
          Column('agent_name', String(255), nullable=False),
          Column('agent_type', String(100), nullable=False),
          Column('provider', String(100), nullable=True),
          Column('model_name', String(255), nullable=True),
          Column('endpoint_url', Text, nullable=True),
          Column('network_location', String(255), nullable=True),
          Column('discovery_method', String(100), nullable=False),
          Column('security_tested', Boolean, nullable=False, default=False),
          Column('vulnerabilities', JSON, nullable=False, default=dict),
          Column('risk_score', Float, nullable=version >= 4,
                 default=None if version >= 4 else 0.0),
          Column('risk_level', String(20), nullable=False, default='unknown'),
          Column('metadata', JSON, nullable=False, default=dict),
          Column('discovered_at', DateTime, nullable=False, default=_time))
    Table('scan_result', metadata,
          Column('scan_id', String(64), primary_key=True),
          Column('result', JSON, nullable=False))
    Table('scan_job', metadata,
          Column('scan_id', String(64), primary_key=True),
          Column('status', String(32), nullable=False, default='queued'),
          Column('owner', String(64), nullable=True),
          Column('created_at', DateTime, nullable=False, default=_time),
          Column('started_at', DateTime, nullable=True),
          Column('completed_at', DateTime, nullable=True))
    Table('schema_version', metadata,
          Column('id', Integer, primary_key=True),
          Column('version', Integer, nullable=False))
    Table('audit_event', metadata,
          Column('id', Integer, primary_key=True, autoincrement=True),
          Column('scan_id', String(64), nullable=False),
          Column('organization_id', String(64), nullable=False),
          Column('event', String(32), nullable=False),
          Column('previous_status', String(32), nullable=True),
          Column('status', String(32), nullable=False),
          Column('created_at', DateTime, nullable=False, default=_time))
    Table('scan_template', metadata,
          Column('id', String(64), primary_key=True),
          Column('organization_id', String(64), nullable=False),
          Column('scan_name', String(255), nullable=False),
          Column('scan_type', String(50), nullable=False),
          Column('target_scope', JSON, nullable=False),
          Column('scan_config', JSON, nullable=False),
          Column('revision', Integer, nullable=False, default=1),
          Column('created_by', String(255), nullable=True),
          Column('created_at', DateTime, nullable=False, default=_time),
          Column('updated_at', DateTime, nullable=False, default=_time))
    Table('scan_schedule', metadata,
          Column('id', String(64), primary_key=True),
          Column('organization_id', String(64), nullable=False),
          Column('template_id', String(64), nullable=False),
          Column('template_revision', Integer, nullable=False),
          Column('interval_seconds', Integer, nullable=False),
          Column('total_runs', Integer, nullable=False),
          Column('admitted_runs', Integer, nullable=False, default=0),
          Column('revision', Integer, nullable=False, default=1),
          Column('state', String(32), nullable=False, default='disabled'),
          Column('pause_reason', String(32), nullable=True),
          Column('next_due_at', DateTime, nullable=True),
          Column('outstanding_scan_id', String(64), nullable=True),
          Column('created_by', String(255), nullable=True),
          Column('created_at', DateTime, nullable=False, default=_time),
          Column('updated_at', DateTime, nullable=False, default=_time))
    Table('scan_occurrence', metadata,
          Column('id', String(64), primary_key=True),
          Column('schedule_id', String(64), nullable=False),
          Column('organization_id', String(64), nullable=False),
          Column('scan_id', String(64), nullable=False),
          Column('ordinal', Integer, nullable=False),
          Column('created_at', DateTime, nullable=False, default=_time))
    Table('inventory_generation', metadata,
          Column('organization_id', String(64), primary_key=True, nullable=False),
          Column('generation', String(32), nullable=False))
    for table, column in (('scan_job', 'status'), ('audit_event', 'scan_id'),
                          ('scan_template', 'organization_id'), ('scan_schedule', 'organization_id'),
                          ('scan_occurrence', 'schedule_id')):
        Index(f'ix_{table}_{column}', metadata.tables[table].c[column])
    if version == 5:
        scans, agents = metadata.tables['scan_session'], metadata.tables['discovered_agent']
        Index('ix_inventory_scan_session_org_id', scans.c.organization_id, scans.c.id)
        Index('ix_inventory_observation_scan_order', agents.c.scan_id, agents.c.discovered_at.desc(), agents.c.id)
        Index('ix_inventory_observation_scan_type_order', agents.c.scan_id, agents.c.agent_type,
              agents.c.discovered_at.desc(), agents.c.id)
        for statement in SCHEMA_FIVE_TRIGGERS.values():
            event.listen(metadata, 'after_create', DDL(statement))
    for name in list(metadata.tables):
        if name not in selected:
            metadata.remove(metadata.tables[name])
    return metadata
