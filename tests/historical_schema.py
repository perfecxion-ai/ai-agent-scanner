"""Frozen historical SQLite fixtures, independent of current ORM metadata."""

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, Column, DDL, DateTime, Float, Index, Integer, JSON, MetaData, String, Table, Text, event


BASE_TABLES = frozenset({'scan_session', 'discovered_agent'})
VERSION_ONE_TABLES = BASE_TABLES | {'scan_result', 'scan_job', 'schema_version', 'audit_event'}
VERSION_TWO_TABLES = VERSION_ONE_TABLES | {'scan_template'}
VERSION_THREE_TABLES = VERSION_TWO_TABLES | {'scan_schedule', 'scan_occurrence'}
VERSION_FOUR_TABLES = VERSION_THREE_TABLES
VERSION_FIVE_TABLES = VERSION_FOUR_TABLES | {'inventory_generation'}
VERSION_SIX_TABLES = VERSION_FIVE_TABLES
VERSION_SEVEN_TABLES = VERSION_SIX_TABLES | {'asset_group_index', 'asset_group_publication'}
LAYOUTS = {0: BASE_TABLES, 1: VERSION_ONE_TABLES, 2: VERSION_TWO_TABLES, 3: VERSION_THREE_TABLES,
           4: VERSION_FOUR_TABLES, 5: VERSION_FIVE_TABLES, 6: VERSION_SIX_TABLES, 7: VERSION_SEVEN_TABLES}

# Exact schema 7 group descriptors captured at 1b164df, without live registrations.
SCHEMA_SEVEN_GROUP_COLUMNS = {
    'asset_group_index': (
        ('organization_id', 'VARCHAR(64)', False), ('build_id', 'VARCHAR(32)', False),
        ('observation_id', 'VARCHAR(64)', False), ('scan_id', 'VARCHAR(64)', False),
        ('report_asset_id', 'VARCHAR(256)', True), ('group_id', 'VARCHAR(64)', False),
        ('identity_status', 'VARCHAR(16)', False), ('unmerged_reason', 'VARCHAR(64)', True),
        ('target', 'JSON', True), ('observed_at_us', 'BIGINT', False),
        ('agent_type', 'VARCHAR(100)', False), ('is_latest', 'BOOLEAN', False),
        ('history_complete', 'BOOLEAN', False), ('group_history_complete', 'BOOLEAN', False),
        ('supported_confirmation_count', 'INTEGER', True), ('archived_claim_count', 'INTEGER', True),
        ('group_observation_count', 'INTEGER', False),
        ('group_supported_confirmation_count', 'INTEGER', True),
        ('group_archived_claim_count', 'INTEGER', True), ('publication_nonce', 'VARCHAR(32)', True),
        ('source_generation', 'VARCHAR(32)', False), ('projection_policy', 'VARCHAR(64)', False),
    ),
    'asset_group_publication': (
        ('organization_id', 'VARCHAR(64)', False), ('active_build_id', 'VARCHAR(32)', True),
        ('active_generation', 'VARCHAR(32)', True), ('active_nonce', 'VARCHAR(32)', True),
        ('active_policy', 'VARCHAR(64)', True), ('active_row_count', 'INTEGER', True),
        ('active_group_count', 'INTEGER', True), ('building_build_id', 'VARCHAR(32)', True),
        ('building_generation', 'VARCHAR(32)', True), ('building_policy', 'VARCHAR(64)', True),
        ('after_scan_id', 'VARCHAR(64)', True), ('after_observation_id', 'VARCHAR(64)', True),
        ('processed_count', 'INTEGER', False), ('error_code', 'VARCHAR(64)', True),
    ),
}
SCHEMA_SEVEN_GROUP_INDEXES = (
    'CREATE UNIQUE INDEX ux_asset_group_head ON asset_group_index (organization_id, build_id, group_id) WHERE is_latest = 1',
    'CREATE INDEX ix_asset_group_head_page ON asset_group_index (organization_id, build_id, publication_nonce, source_generation, projection_policy, is_latest, observed_at_us DESC, group_id)',
    'CREATE INDEX ix_asset_group_history ON asset_group_index (organization_id, build_id, publication_nonce, source_generation, projection_policy, group_id, observed_at_us DESC, observation_id)',
)
SCHEMA_SEVEN_GROUP_TRIGGERS = (
    'CREATE TRIGGER aiscan_asset_group_index_insert AFTER INSERT ON asset_group_index WHEN NEW.publication_nonce IS NOT NULL OR EXISTS (SELECT 1 FROM asset_group_publication WHERE organization_id = NEW.organization_id AND active_build_id = NEW.build_id) BEGIN UPDATE asset_group_publication SET active_build_id = NULL, active_generation = NULL, active_nonce = NULL, active_policy = NULL, active_row_count = NULL, active_group_count = NULL WHERE organization_id = NEW.organization_id AND active_build_id = NEW.build_id;UPDATE asset_group_index SET publication_nonce = NULL WHERE organization_id = NEW.organization_id AND build_id = NEW.build_id AND observation_id = NEW.observation_id AND publication_nonce IS NOT NULL; END',
    'CREATE TRIGGER aiscan_asset_group_index_update AFTER UPDATE ON asset_group_index WHEN OLD.publication_nonce IS NOT NULL OR EXISTS (SELECT 1 FROM asset_group_publication WHERE organization_id = OLD.organization_id AND active_build_id = OLD.build_id) OR EXISTS (SELECT 1 FROM asset_group_publication WHERE organization_id = NEW.organization_id AND active_build_id = NEW.build_id) BEGIN UPDATE asset_group_publication SET active_build_id = NULL, active_generation = NULL, active_nonce = NULL, active_policy = NULL, active_row_count = NULL, active_group_count = NULL WHERE organization_id = OLD.organization_id AND active_build_id = OLD.build_id;UPDATE asset_group_publication SET active_build_id = NULL, active_generation = NULL, active_nonce = NULL, active_policy = NULL, active_row_count = NULL, active_group_count = NULL WHERE organization_id = NEW.organization_id AND active_build_id = NEW.build_id;UPDATE asset_group_index SET publication_nonce = NULL WHERE organization_id = NEW.organization_id AND build_id = NEW.build_id AND observation_id = NEW.observation_id AND publication_nonce IS NOT NULL; END',
    'CREATE TRIGGER aiscan_asset_group_index_delete AFTER DELETE ON asset_group_index WHEN OLD.publication_nonce IS NOT NULL OR EXISTS (SELECT 1 FROM asset_group_publication WHERE organization_id = OLD.organization_id AND active_build_id = OLD.build_id) BEGIN UPDATE asset_group_publication SET active_build_id = NULL, active_generation = NULL, active_nonce = NULL, active_policy = NULL, active_row_count = NULL, active_group_count = NULL WHERE organization_id = OLD.organization_id AND active_build_id = OLD.build_id; END',
)

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
    if not selected <= VERSION_SEVEN_TABLES:
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
    # Schema 6 changed the evidence policy, preserving the schema 5 physical DDL.
    if version in {5, 6, 7}:
        scans, agents = metadata.tables['scan_session'], metadata.tables['discovered_agent']
        Index('ix_inventory_scan_session_org_id', scans.c.organization_id, scans.c.id)
        Index('ix_inventory_observation_scan_order', agents.c.scan_id, agents.c.discovered_at.desc(), agents.c.id)
        Index('ix_inventory_observation_scan_type_order', agents.c.scan_id, agents.c.agent_type,
              agents.c.discovered_at.desc(), agents.c.id)
        for statement in SCHEMA_FIVE_TRIGGERS.values():
            event.listen(metadata, 'after_create', DDL(statement))
    if version == 7:
        primary = {'asset_group_index': {'organization_id', 'build_id', 'observation_id'},
                   'asset_group_publication': {'organization_id'}}
        for name, columns in SCHEMA_SEVEN_GROUP_COLUMNS.items():
            def old_type(kind):
                return (String(int(kind[8:-1])) if kind.startswith('VARCHAR(')
                        else {'BIGINT': BigInteger, 'BOOLEAN': Boolean, 'INTEGER': Integer, 'JSON': JSON}[kind]())
            Table(name, metadata, *(Column(column, old_type(kind), nullable=nullable,
                                          primary_key=column in primary[name])
                                   for column, kind, nullable in columns))
        for statement in SCHEMA_SEVEN_GROUP_INDEXES + SCHEMA_SEVEN_GROUP_TRIGGERS:
            event.listen(metadata, 'after_create', DDL(statement))
    for name in list(metadata.tables):
        if name not in selected:
            metadata.remove(metadata.tables[name])
    return metadata
