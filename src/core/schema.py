"""Explicit transactional SQLite upgrades for the supported single-process server."""

import json
import re

from sqlalchemy import DDL, LargeBinary, MetaData, case, cast, func, inspect, insert, literal, select, update

from src.core.stored_risk import (
    MAX_STORED_RISK_BYTES, project_stored_risk, snapshot_stored_risk, stored_json_text,
)


SCHEMA_VERSION = 4
BASE_TABLES = frozenset({"scan_session", "discovered_agent"})
LEGACY_LAYOUTS = (BASE_TABLES, BASE_TABLES | {"scan_result"},
                  BASE_TABLES | {"scan_result", "scan_job"})
VERSION_ONE_TABLES = BASE_TABLES | {"scan_result", "scan_job", "schema_version", "audit_event"}
VERSION_TWO_TABLES = VERSION_ONE_TABLES | {"scan_template"}
VERSION_THREE_TABLES = VERSION_TWO_TABLES | {"scan_schedule", "scan_occurrence"}
VERSION_FOUR_TABLES = VERSION_THREE_TABLES
_NULLABLE_SCORES = {("scan_session", "overall_risk_score"), ("discovered_agent", "risk_score")}
_INVALID_JSON = object()
_DDL_QUOTES = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|`(?:``|[^`])*`|\[[^\]]*\]|--[^\r\n]*|/\*[\s\S]*?\*/")


class SchemaError(RuntimeError):
    """A database does not match an explicitly supported schema."""


# Frozen descriptors from the supported pre-nullable layouts. Do not derive
# historical validation from the application models being upgraded.
_HISTORICAL = {
    'audit_event': (
        ('id', 'INTEGER', False),
        ('scan_id', 'VARCHAR(64)', False),
        ('organization_id', 'VARCHAR(64)', False),
        ('event', 'VARCHAR(32)', False),
        ('previous_status', 'VARCHAR(32)', True),
        ('status', 'VARCHAR(32)', False),
        ('created_at', 'DATETIME', False),
    ),
    'discovered_agent': (
        ('id', 'VARCHAR(64)', False),
        ('scan_id', 'VARCHAR(64)', False),
        ('agent_name', 'VARCHAR(255)', False),
        ('agent_type', 'VARCHAR(100)', False),
        ('provider', 'VARCHAR(100)', True),
        ('model_name', 'VARCHAR(255)', True),
        ('endpoint_url', 'TEXT', True),
        ('network_location', 'VARCHAR(255)', True),
        ('discovery_method', 'VARCHAR(100)', False),
        ('security_tested', 'BOOLEAN', False),
        ('vulnerabilities', 'JSON', False),
        ('risk_score', 'FLOAT', False),
        ('risk_level', 'VARCHAR(20)', False),
        ('metadata', 'JSON', False),
        ('discovered_at', 'DATETIME', False),
    ),
    'scan_job': (
        ('scan_id', 'VARCHAR(64)', False),
        ('status', 'VARCHAR(32)', False),
        ('owner', 'VARCHAR(64)', True),
        ('created_at', 'DATETIME', False),
        ('started_at', 'DATETIME', True),
        ('completed_at', 'DATETIME', True),
    ),
    'scan_occurrence': (
        ('id', 'VARCHAR(64)', False),
        ('schedule_id', 'VARCHAR(64)', False),
        ('organization_id', 'VARCHAR(64)', False),
        ('scan_id', 'VARCHAR(64)', False),
        ('ordinal', 'INTEGER', False),
        ('created_at', 'DATETIME', False),
    ),
    'scan_result': (
        ('scan_id', 'VARCHAR(64)', False),
        ('result', 'JSON', False),
    ),
    'scan_schedule': (
        ('id', 'VARCHAR(64)', False),
        ('organization_id', 'VARCHAR(64)', False),
        ('template_id', 'VARCHAR(64)', False),
        ('template_revision', 'INTEGER', False),
        ('interval_seconds', 'INTEGER', False),
        ('total_runs', 'INTEGER', False),
        ('admitted_runs', 'INTEGER', False),
        ('revision', 'INTEGER', False),
        ('state', 'VARCHAR(32)', False),
        ('pause_reason', 'VARCHAR(32)', True),
        ('next_due_at', 'DATETIME', True),
        ('outstanding_scan_id', 'VARCHAR(64)', True),
        ('created_by', 'VARCHAR(255)', True),
        ('created_at', 'DATETIME', False),
        ('updated_at', 'DATETIME', False),
    ),
    'scan_session': (
        ('id', 'VARCHAR(64)', False),
        ('organization_id', 'VARCHAR(64)', False),
        ('scan_name', 'VARCHAR(255)', False),
        ('scan_type', 'VARCHAR(50)', False),
        ('status', 'VARCHAR(50)', False),
        ('progress', 'FLOAT', False),
        ('target_scope', 'JSON', False),
        ('scan_config', 'JSON', False),
        ('agents_discovered', 'INTEGER', False),
        ('vulnerabilities_found', 'INTEGER', False),
        ('critical_risks', 'INTEGER', False),
        ('overall_risk_score', 'FLOAT', False),
        ('created_at', 'DATETIME', False),
        ('started_at', 'DATETIME', True),
        ('completed_at', 'DATETIME', True),
        ('created_by', 'VARCHAR(255)', True),
        ('user_ip', 'VARCHAR(45)', True),
    ),
    'scan_template': (
        ('id', 'VARCHAR(64)', False),
        ('organization_id', 'VARCHAR(64)', False),
        ('scan_name', 'VARCHAR(255)', False),
        ('scan_type', 'VARCHAR(50)', False),
        ('target_scope', 'JSON', False),
        ('scan_config', 'JSON', False),
        ('revision', 'INTEGER', False),
        ('created_by', 'VARCHAR(255)', True),
        ('created_at', 'DATETIME', False),
        ('updated_at', 'DATETIME', False),
    ),
    'schema_version': (
        ('id', 'INTEGER', False),
        ('version', 'INTEGER', False),
    ),
}
_PRIMARY = {'audit_event':['id'],'discovered_agent':['id'],'scan_job':['scan_id'],'scan_occurrence':['id'],'scan_result':['scan_id'],'scan_schedule':['id'],'scan_session':['id'],'scan_template':['id'],'schema_version':['id']}


def _columns(name, version):
    return {column: (kind, True if version == 4 and (name, column) in _NULLABLE_SCORES else nullable)
            for column, kind, nullable in _HISTORICAL[name]}


def _validate_metadata(metadata, dialect):
    if set(metadata.tables) != VERSION_FOUR_TABLES:
        raise SchemaError("Unsupported application metadata")
    for name, table in metadata.tables.items():
        options = table.dialect_options['sqlite']
        if (options.get('with_rowid', True) is not True or options.get('strict', False) is not False
                or options.get('autoincrement', False) is not False):
            raise SchemaError("Unsupported application metadata")
        expected = _columns(name, 4)
        if set(table.columns.keys()) != set(expected):
            raise SchemaError("Unsupported application metadata")
        for column in table.columns:
            if ((str(column.type.compile(dialect=dialect)).upper(), column.nullable) != expected[column.name]
                    or column.server_default is not None or column.computed is not None
                    or column.identity is not None):
                raise SchemaError("Unsupported application metadata")
        if [column.name for column in table.primary_key.columns] != _PRIMARY[name]:
            raise SchemaError("Unsupported application metadata")


def _validate_indexes(connection, name):
    quoted = connection.dialect.identifier_preparer.quote(name)
    for index in connection.exec_driver_sql("PRAGMA index_list(" + quoted + ")").mappings():
        if index["origin"] == "pk":
            continue
        if index["unique"]:
            raise SchemaError("Unsupported unique index in " + name)
        index_name = connection.dialect.identifier_preparer.quote(index["name"])
        for column in connection.exec_driver_sql("PRAGMA index_xinfo(" + index_name + ")").mappings():
            if column["key"] and column["cid"] < 0:
                raise SchemaError("Unsupported expression index in " + name)


def _validate_table_options(connection, name):
    definition = connection.exec_driver_sql(
        "SELECT CASE WHEN length(CAST(sql AS BLOB)) <= 65536 THEN sql END "
        "FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).scalar_one()
    if not isinstance(definition, str):
        raise SchemaError("Unsupported table definition in " + name)
    # Quoted identifiers, literals and comments are not SQL option keywords.
    words = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', _DDL_QUOTES.sub(' ', definition).upper())
    if ('COLLATE' in words or 'STRICT' in words or 'CONFLICT' in words
            or any(pair == ('WITHOUT', 'ROWID') for pair in zip(words, words[1:]))):
        raise SchemaError("Unsupported table options or collations in " + name)


def _validate_tables(connection, names, version):
    inspector = inspect(connection)
    for name in sorted(names):
        _validate_table_options(connection, name)
        expected = _columns(name, version)
        actual = {column["name"]: column for column in inspector.get_columns(name)}
        if set(actual) != set(expected):
            raise SchemaError(f"Unsupported columns in {name}; restore or migrate the database explicitly")
        for column, definition in expected.items():
            stored = actual[column]
            if ((str(stored["type"]).upper(), stored["nullable"]) != definition
                    or stored.get("computed") is not None or stored.get("identity") is not None):
                raise SchemaError(f"Unsupported definition for {name}.{column}")
            if stored["default"] is not None:
                raise SchemaError(f"Unsupported database default for {name}.{column}")
        if inspector.get_pk_constraint(name)["constrained_columns"] != _PRIMARY[name]:
            raise SchemaError(f"Unsupported primary key in {name}")
        _validate_indexes(connection, name)
        if (inspector.get_foreign_keys(name) or inspector.get_check_constraints(name)
                or inspector.get_unique_constraints(name)):
            raise SchemaError(f"Unsupported additional constraints in {name}")


def _rebuild_score_table(connection, metadata, name):
    indexes = connection.exec_driver_sql(
        "SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND sql IS NOT NULL",
        (name,)).scalars().all()
    original = metadata.tables[name]
    temporary_name = "_aiscan_v4_" + name
    temporary = original.to_metadata(MetaData(), name=temporary_name)
    temporary.indexes.clear()
    temporary.create(connection)
    expressions = [
        literal(None) if (name, column.name) in _NULLABLE_SCORES
        else literal("unknown") if column.name == "risk_level" else original.c[column.name]
        for column in original.columns
    ]
    # SQL copying preserves stored JSON/text bytes instead of deserializing them.
    connection.execute(insert(temporary).from_select(
        [column.name for column in temporary.columns], select(*expressions)))
    original.drop(connection)
    quote = connection.dialect.identifier_preparer.quote
    connection.execute(DDL("ALTER TABLE %(old)s RENAME TO %(new)s",
                           context={"old": quote(temporary_name), "new": quote(name)}))
    for definition in indexes:
        connection.exec_driver_sql(definition)


def _bounded_blob(column):
    raw = cast(column, LargeBinary)
    return case((func.length(raw) <= MAX_STORED_RISK_BYTES, raw), else_=None)


def _decode(raw):
    text = stored_json_text(raw)
    if text is None:
        return _INVALID_JSON
    try:
        return json.loads(text)
    except (ValueError, TypeError, RecursionError, OverflowError, UnicodeError):
        return _INVALID_JSON


def _report_for_scan(connection, metadata, identifier):
    scans, reports = metadata.tables["scan_session"], metadata.tables["scan_result"]
    raw = connection.scalar(select(_bounded_blob(reports.c.result)).select_from(
        scans.outerjoin(reports, scans.c.id == reports.c.scan_id)).where(scans.c.id == identifier))
    return project_stored_risk(_decode(raw))


def _migrate_risk_values(connection, metadata):
    scans, reports, snapshots = (metadata.tables[name] for name in
                                 ("scan_session", "scan_result", "discovered_agent"))
    # No all-database Python cache: each bounded archive is interpreted independently.
    statement = select(scans.c.id, _bounded_blob(reports.c.result)).select_from(
        scans.outerjoin(reports, scans.c.id == reports.c.scan_id)).order_by(scans.c.id)
    with connection.execute(statement) as rows:
        for identifier, raw in rows:
            summary, _ = project_stored_risk(_decode(raw))
            connection.execute(update(scans).where(scans.c.id == identifier).values(
                overall_risk_score=summary["overall_risk_score"]))
    current_scan, projected = object(), {}
    statement = select(snapshots.c.id, snapshots.c.scan_id, _bounded_blob(snapshots.c.metadata)).order_by(
        snapshots.c.scan_id, snapshots.c.id)
    with connection.execute(statement) as rows:
        for identifier, scan_id, raw in rows:
            if scan_id != current_scan:
                _, projected = _report_for_scan(connection, metadata, scan_id)
                current_scan = scan_id
            stored = _decode(raw)
            score, level = ((None, "unknown") if stored is _INVALID_JSON else
                            snapshot_stored_risk(projected, identifier, stored))
            connection.execute(update(snapshots).where(snapshots.c.id == identifier).values(
                risk_score=score, risk_level=level))


def initialize_schema(engine, metadata):
    """Upgrade only recognized schemas; preserve archives and logical row identities."""
    if engine.dialect.name != "sqlite":
        raise SchemaError("Schema initialization currently supports SQLite only")
    _validate_metadata(metadata, engine.dialect)
    expected = VERSION_FOUR_TABLES
    with engine.connect() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            names = set(inspect(connection).get_table_names())
            if (inspect(connection).get_view_names() or connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger'").first()):
                raise SchemaError("Unknown database views or triggers; no automatic changes were made")
            if names - expected:
                raise SchemaError("Unknown database tables; no automatic changes were made")
            if "schema_version" in names:
                _validate_tables(connection, {"schema_version"}, 3)
                rows = connection.execute(select(metadata.tables["schema_version"])).all()
                if len(rows) != 1 or rows[0][0] != 1 or rows[0][1] not in (1, 2, 3, 4):
                    raise SchemaError("Unsupported database schema version")
                version = rows[0][1]
                layouts = {1: VERSION_ONE_TABLES, 2: VERSION_TWO_TABLES,
                           3: VERSION_THREE_TABLES, 4: VERSION_FOUR_TABLES}
                if names != layouts[version]:
                    raise SchemaError("Versioned database has missing or unexpected tables")
                _validate_tables(connection, names, version)
                if version < 4:
                    if version == 1:
                        metadata.tables["scan_template"].create(connection)
                    if version in (1, 2):
                        metadata.tables["scan_schedule"].create(connection)
                        metadata.tables["scan_occurrence"].create(connection)
                    for name in sorted(BASE_TABLES):
                        _rebuild_score_table(connection, metadata, name)
                    _migrate_risk_values(connection, metadata)
                    connection.execute(update(metadata.tables["schema_version"]).where(
                        metadata.tables["schema_version"].c.id == 1).values(version=SCHEMA_VERSION))
            else:
                if names and names not in LEGACY_LAYOUTS:
                    raise SchemaError("Unrecognized legacy database layout")
                _validate_tables(connection, names, 3)
                metadata.create_all(connection)
                if names:
                    for name in sorted(BASE_TABLES):
                        _rebuild_score_table(connection, metadata, name)
                    _migrate_risk_values(connection, metadata)
                connection.execute(insert(metadata.tables["schema_version"]).values(
                    id=1, version=SCHEMA_VERSION))
            _validate_tables(connection, expected, 4)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
