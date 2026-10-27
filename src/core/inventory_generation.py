"""Recognized SQLite invalidation for paginated observation reads."""

from sqlalchemy import Column, DDL, Index, String, Table
from sqlalchemy.dialects.sqlite import dialect
from sqlalchemy.schema import CreateIndex


TABLE_NAME = 'inventory_generation'
INDEX_DEFINITIONS = {
    'ix_inventory_scan_session_org_id':
        'CREATE INDEX ix_inventory_scan_session_org_id ON scan_session (organization_id, id)',
    'ix_inventory_observation_scan_order':
        'CREATE INDEX ix_inventory_observation_scan_order ON discovered_agent (scan_id, discovered_at DESC, id)',
    'ix_inventory_observation_scan_type_order':
        'CREATE INDEX ix_inventory_observation_scan_type_order ON discovered_agent (scan_id, agent_type, discovered_at DESC, id)',
}
INDEX_NAMES = frozenset(INDEX_DEFINITIONS)


class InventorySchemaError(RuntimeError):
    """Inventory consistency requires the recognized database definitions."""


def _sql(statement, **context):
    # Context contains only fixed SQL identifiers and row references below.
    return str(DDL(statement, context=context).compile(dialect=dialect())).strip().rstrip(';')


def _touch_owner(reference):
    return _sql(
        "INSERT INTO inventory_generation (organization_id, generation) "
        "SELECT organization_id, lower(hex(randomblob(16))) FROM scan_session WHERE id = %(reference)s "
        "ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation;",
        reference=reference) + ';'


def _touch_organization(reference):
    return _sql(
        "INSERT INTO inventory_generation (organization_id, generation) "
        "VALUES (%(reference)s, lower(hex(randomblob(16)))) "
        "ON CONFLICT (organization_id) DO UPDATE SET generation = excluded.generation;",
        reference=reference) + ';'


def _trigger(name, event, table, statements, condition=''):
    return _sql('CREATE TRIGGER %(name)s AFTER %(event)s ON %(table)s %(condition)s BEGIN %(statements)s END',
                name=name, event=event, table=table, condition=condition, statements=statements)


TRIGGER_DEFINITIONS = {}
for _subject, _table in (('observation', 'discovered_agent'), ('report', 'scan_result')):
    for _event in ('insert', 'update', 'delete'):
        _name = 'aiscan_inventory_' + _subject + '_' + _event
        _statements = (_touch_owner('OLD.scan_id') if _event != 'insert' else '')
        _statements += (_touch_owner('NEW.scan_id') if _event != 'delete' else '')
        TRIGGER_DEFINITIONS[_name] = _trigger(_name, _event.upper(), _table, _statements)
for _event, _reference in (('insert', 'NEW'), ('delete', 'OLD')):
    _name = 'aiscan_inventory_session_' + _event
    TRIGGER_DEFINITIONS[_name] = _trigger(
        _name, _event.upper(), 'scan_session', _touch_organization(_reference + '.organization_id'),
        _sql('WHEN EXISTS (SELECT 1 FROM discovered_agent WHERE scan_id = %(reference)s)',
             reference=_reference + '.id'))
TRIGGER_DEFINITIONS['aiscan_inventory_session_update'] = _trigger(
    'aiscan_inventory_session_update', 'UPDATE OF id, organization_id', 'scan_session',
    _touch_organization('OLD.organization_id') + _touch_organization('NEW.organization_id'),
    'WHEN OLD.id IS NOT NEW.id OR OLD.organization_id IS NOT NEW.organization_id')


def register_inventory_metadata(metadata):
    """Register the generation table and candidate indexes after the models."""
    table = metadata.tables.get(TABLE_NAME)
    if table is None:
        table = Table(TABLE_NAME, metadata,
                      Column('organization_id', String(64), primary_key=True, nullable=False),
                      Column('generation', String(32), nullable=False))
    scans, observations = metadata.tables['scan_session'], metadata.tables['discovered_agent']
    columns = {
        'ix_inventory_scan_session_org_id': (scans.c.organization_id, scans.c.id),
        'ix_inventory_observation_scan_order': (observations.c.scan_id, observations.c.discovered_at.desc(), observations.c.id),
        'ix_inventory_observation_scan_type_order': (
            observations.c.scan_id, observations.c.agent_type, observations.c.discovered_at.desc(), observations.c.id),
    }
    for name, expressions in columns.items():
        existing = [index for item in metadata.tables.values() for index in item.indexes
                    if index.name is not None and index.name.casefold() == name.casefold()]
        if not existing:
            Index(name, *expressions)
        elif (len(existing) != 1 or str(CreateIndex(existing[0]).compile(dialect=dialect())).strip()
              != INDEX_DEFINITIONS[name]):
            raise InventorySchemaError('Reserved inventory index metadata conflicts')
    return table


def validate_inventory_definitions(connection, version):
    """Old versions permit no triggers; schema 5 requires exactly this set."""
    triggers = dict(connection.exec_driver_sql(
        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'").all())
    if version < 5:
        if triggers:
            raise InventorySchemaError('Unknown database triggers; no automatic changes were made')
    else:
        expected = TRIGGER_DEFINITIONS
        if version >= 7:
            from src.core.asset_group_storage import TRIGGER_DEFINITIONS as group_triggers
            expected = {**expected, **group_triggers}
        if triggers != expected:
            raise InventorySchemaError('Missing or altered inventory generation triggers')
    indexes = dict(connection.exec_driver_sql(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index'").all())
    reserved = {name.casefold(): name for name in INDEX_DEFINITIONS}
    if any(name.casefold() in reserved and name != reserved[name.casefold()] for name in indexes):
        raise InventorySchemaError('Reserved inventory index definition conflicts')
    for name, expected in INDEX_DEFINITIONS.items():
        if name in indexes and indexes[name] != expected:
            raise InventorySchemaError('Reserved inventory index definition conflicts')
        if version >= 5 and name not in indexes:
            raise InventorySchemaError('Missing inventory candidate index')


def install_inventory_generation(connection, metadata):
    """Install only during an owned schema upgrade; repeat startup never churns tokens."""
    metadata.tables[TABLE_NAME].create(connection, checkfirst=True)
    indexes = {index.name: index for table in metadata.tables.values() for index in table.indexes}
    for name in sorted(INDEX_NAMES):
        indexes[name].create(connection, checkfirst=True)
    connection.exec_driver_sql(
        "INSERT INTO inventory_generation (organization_id, generation) "
        "SELECT owners.organization_id, lower(hex(randomblob(16))) "
        "FROM (SELECT DISTINCT organization_id FROM scan_session) AS owners WHERE 1 "
        "ON CONFLICT (organization_id) DO NOTHING")
    for statement in TRIGGER_DEFINITIONS.values():
        connection.exec_driver_sql(statement)
