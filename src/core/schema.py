"""Explicit additive SQLite upgrades for the supported single-process server."""

from sqlalchemy import inspect, insert, select


SCHEMA_VERSION = 1
BASE_TABLES = frozenset({"scan_session", "discovered_agent"})
LEGACY_LAYOUTS = (BASE_TABLES, BASE_TABLES | {"scan_result"},
                  BASE_TABLES | {"scan_result", "scan_job"})


class SchemaError(RuntimeError):
    """A database does not match an explicitly supported schema."""


def _validate_tables(connection, metadata, names):
    inspector = inspect(connection)
    for name in names:
        expected = metadata.tables[name]
        actual = {column["name"]: column for column in inspector.get_columns(name)}
        if set(actual) != set(expected.columns.keys()):
            raise SchemaError(f"Unsupported columns in {name}; restore or migrate the database explicitly")
        for column in expected.columns:
            stored = actual[column.name]
            if (str(stored["type"]).upper() != str(column.type.compile(dialect=connection.dialect)).upper()
                    or stored["nullable"] != column.nullable):
                raise SchemaError(f"Unsupported definition for {name}.{column.name}")
            expected_default = str(column.server_default.arg) if column.server_default is not None else None
            if stored["default"] != expected_default:
                raise SchemaError(f"Unsupported database default for {name}.{column.name}")
        primary = inspector.get_pk_constraint(name)["constrained_columns"]
        if primary != [column.name for column in expected.primary_key.columns]:
            raise SchemaError(f"Unsupported primary key in {name}")
        if (inspector.get_foreign_keys(name) or inspector.get_check_constraints(name)
                or inspector.get_unique_constraints(name)):
            raise SchemaError(f"Unsupported additional constraints in {name}")
        if any(index["unique"] for index in inspector.get_indexes(name)):
            raise SchemaError(f"Unsupported unique index in {name}")


def initialize_schema(engine, metadata):
    """Upgrade recognized legacy databases without altering existing tables or rows."""
    if engine.dialect.name != "sqlite":
        raise SchemaError("Schema initialization currently supports SQLite only")
    expected = set(metadata.tables)
    with engine.connect() as connection:
        # SQLite otherwise may autocommit DDL before a transaction has begun.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            names = set(inspect(connection).get_table_names())
            if (inspect(connection).get_view_names() or connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger'").first()):
                raise SchemaError("Unknown database views or triggers; no automatic changes were made")
            if names - expected:
                raise SchemaError("Unknown database tables; no automatic changes were made")
            if "schema_version" in names:
                if names != expected:
                    raise SchemaError("Versioned database has missing tables")
                _validate_tables(connection, metadata, names)
                rows = connection.execute(select(metadata.tables["schema_version"])).all()
                if len(rows) != 1 or rows[0] != (1, SCHEMA_VERSION):
                    raise SchemaError("Unsupported database schema version")
            else:
                if names and names not in LEGACY_LAYOUTS:
                    raise SchemaError("Unrecognized legacy database layout")
                _validate_tables(connection, metadata, names)
                metadata.create_all(connection)
                connection.execute(insert(metadata.tables["schema_version"]).values(
                    id=1, version=SCHEMA_VERSION))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
