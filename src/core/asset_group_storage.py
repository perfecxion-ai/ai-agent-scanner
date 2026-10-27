"""Recognized storage for derived public-target groups, without risk verdicts."""

from sqlalchemy import BigInteger, Boolean, Column, DDL, Index, Integer, JSON, String, Table, text
from sqlalchemy.dialects.sqlite import dialect
from sqlalchemy.schema import CreateIndex


INDEX_TABLE = 'asset_group_index'
PUBLICATION_TABLE = 'asset_group_publication'
TABLE_NAMES = frozenset({INDEX_TABLE, PUBLICATION_TABLE})
# SQL type and nullability are explicit schema descriptors, not ORM reflection.
COLUMNS = {
    INDEX_TABLE: (
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
    PUBLICATION_TABLE: (
        ('organization_id', 'VARCHAR(64)', False), ('active_build_id', 'VARCHAR(32)', True),
        ('active_generation', 'VARCHAR(32)', True), ('active_nonce', 'VARCHAR(32)', True),
        ('active_policy', 'VARCHAR(64)', True), ('active_row_count', 'INTEGER', True),
        ('active_group_count', 'INTEGER', True), ('building_build_id', 'VARCHAR(32)', True),
        ('building_generation', 'VARCHAR(32)', True), ('building_policy', 'VARCHAR(64)', True),
        ('after_scan_id', 'VARCHAR(64)', True), ('after_observation_id', 'VARCHAR(64)', True),
        ('processed_count', 'INTEGER', False), ('error_code', 'VARCHAR(64)', True),
    ),
}
PRIMARY_KEYS = {INDEX_TABLE: ('organization_id', 'build_id', 'observation_id'),
                PUBLICATION_TABLE: ('organization_id',)}
INDEX_DEFINITIONS = {
    'ux_asset_group_head': 'CREATE UNIQUE INDEX ux_asset_group_head ON asset_group_index (organization_id, build_id, group_id) WHERE is_latest = 1',
    'ix_asset_group_head_page': 'CREATE INDEX ix_asset_group_head_page ON asset_group_index (organization_id, build_id, publication_nonce, source_generation, projection_policy, is_latest, observed_at_us DESC, group_id)',
    'ix_asset_group_history': 'CREATE INDEX ix_asset_group_history ON asset_group_index (organization_id, build_id, publication_nonce, source_generation, projection_policy, group_id, observed_at_us DESC, observation_id)',
}
INDEX_NAMES = frozenset(INDEX_DEFINITIONS)
UNIQUE_HEAD_INDEX = 'ux_asset_group_head'
ACTIVE_FIELDS = ('active_build_id', 'active_generation', 'active_nonce', 'active_policy',
                 'active_row_count', 'active_group_count')


class AssetGroupSchemaError(RuntimeError):
    """Only recognized group storage can participate in publication."""


def _active(reference):
    return str(DDL('EXISTS (SELECT 1 FROM asset_group_publication '
                   'WHERE organization_id = %(reference)s.organization_id '
                   'AND active_build_id = %(reference)s.build_id)',
                   context={'reference': reference}).compile(dialect=dialect()))


def _invalidate(reference):
    # DDL context consists only of fixed identifiers and OLD/NEW row references.
    fields = ', '.join(name + ' = NULL' for name in ACTIVE_FIELDS)
    return str(DDL('UPDATE asset_group_publication SET %(fields)s '
                   'WHERE organization_id = %(reference)s.organization_id '
                   'AND active_build_id = %(reference)s.build_id;',
                   context={'fields': fields, 'reference': reference}).compile(dialect=dialect()))


def _unseal():
    return ('UPDATE asset_group_index SET publication_nonce = NULL WHERE organization_id = NEW.organization_id '
            'AND build_id = NEW.build_id AND observation_id = NEW.observation_id '
            'AND publication_nonce IS NOT NULL;')


TRIGGER_DEFINITIONS = {
    'aiscan_asset_group_index_insert':
        f'CREATE TRIGGER aiscan_asset_group_index_insert AFTER INSERT ON {INDEX_TABLE} '
        f'WHEN NEW.publication_nonce IS NOT NULL OR {_active("NEW")} BEGIN '
        + _invalidate('NEW') + _unseal() + ' END',
    'aiscan_asset_group_index_update':
        f'CREATE TRIGGER aiscan_asset_group_index_update AFTER UPDATE ON {INDEX_TABLE} '
        f'WHEN OLD.publication_nonce IS NOT NULL OR {_active("OLD")} OR {_active("NEW")} BEGIN '
        + _invalidate('OLD') + _invalidate('NEW') + _unseal() + ' END',
    'aiscan_asset_group_index_delete':
        f'CREATE TRIGGER aiscan_asset_group_index_delete AFTER DELETE ON {INDEX_TABLE} '
        f'WHEN OLD.publication_nonce IS NOT NULL OR {_active("OLD")} BEGIN '
        + _invalidate('OLD') + ' END',
}


def _column_type(definition):
    if definition.startswith('VARCHAR('):
        return String(int(definition[8:-1]))
    return {'BIGINT': BigInteger, 'BOOLEAN': Boolean, 'INTEGER': Integer, 'JSON': JSON}[definition]()


def register_asset_group_metadata(metadata):
    """Register after application models; historical metadata stays independent."""
    for name, columns in COLUMNS.items():
        if name not in metadata.tables:
            Table(name, metadata, *(Column(column, _column_type(kind), nullable=nullable,
                                          primary_key=column in PRIMARY_KEYS[name],
                                          default=0 if column in {'processed_count', 'group_observation_count'} else None)
                                   for column, kind, nullable in columns))
        table = metadata.tables[name]
        if (tuple(column.name for column in table.primary_key.columns) != PRIMARY_KEYS[name]
                or set(table.columns.keys()) != {column for column, _, _ in columns}
                or any((str(table.c[column].type.compile(dialect=dialect())).upper(),
                        table.c[column].nullable) != (kind, nullable)
                       or table.c[column].server_default is not None
                       or table.c[column].computed is not None or table.c[column].identity is not None
                       for column, kind, nullable in columns)):
            raise AssetGroupSchemaError('Asset-group table metadata conflicts')
    table = metadata.tables[INDEX_TABLE]
    c = table.c
    specs = {
        UNIQUE_HEAD_INDEX: ((c.organization_id, c.build_id, c.group_id),
                            {'unique': True, 'sqlite_where': text('is_latest = 1')}),
        'ix_asset_group_head_page': ((c.organization_id, c.build_id, c.publication_nonce,
                                      c.source_generation, c.projection_policy, c.is_latest,
                                      c.observed_at_us.desc(), c.group_id), {}),
        'ix_asset_group_history': ((c.organization_id, c.build_id, c.publication_nonce,
                                   c.source_generation, c.projection_policy, c.group_id,
                                   c.observed_at_us.desc(), c.observation_id), {}),
    }
    for name, (columns, options) in specs.items():
        matches = [index for item in metadata.tables.values() for index in item.indexes
                   if index.name is not None and index.name.casefold() == name.casefold()]
        if not matches:
            Index(name, *columns, **options)
        elif (len(matches) != 1 or str(CreateIndex(matches[0]).compile(dialect=dialect())).strip()
              != INDEX_DEFINITIONS[name]):
            raise AssetGroupSchemaError('Reserved asset-group index metadata conflicts')
    return table, metadata.tables[PUBLICATION_TABLE]


def validate_asset_group_definitions(connection, version):
    indexes = dict(connection.exec_driver_sql("SELECT name,sql FROM sqlite_master WHERE type = 'index'").all())
    reserved = {name.casefold(): name for name in INDEX_NAMES}
    for name, definition in indexes.items():
        if name.casefold() in reserved and (name != reserved[name.casefold()] or definition != INDEX_DEFINITIONS[name]):
            raise AssetGroupSchemaError('Reserved asset-group index definition conflicts')
    if version >= 7 and not INDEX_NAMES <= indexes.keys():
        raise AssetGroupSchemaError('Missing asset-group index')


def install_asset_group_storage(connection, metadata):
    for name in sorted(TABLE_NAMES):
        metadata.tables[name].create(connection, checkfirst=True)
    for definition in TRIGGER_DEFINITIONS.values():
        connection.exec_driver_sql(definition)
