"""@file t1ote_sql.py
@brief PostgreSQL output for the Tenable OT export: write straight to a database (`--db`) and/or to a
       reviewable `.sql` script (`--sql-out`).

@details Library module (no command line of its own). Both outputs come from the same table
definitions, so the script is exactly what `--db` would run. Each run *replaces* the contents of
the tables (like `--powerbi`) inside one transaction, so a failed run leaves the previous data in
place. Tables are created on first use and new columns are added when a run has more columns than
the table (for example after a custom field is added in the console); nothing is ever dropped.

The Python driver (`psycopg` 3) is imported only when `--db` is used, so the rest of the tool
needs no extra package. Values are sent as parameters or `COPY` data, never pasted into SQL;
only the `.sql` script contains literals, which are escaped by `sql_literal()`.

Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import t1ote_core as hx
from t1ote_core import ExportError, log

## @brief Power BI type name -> PostgreSQL type.
PG_TYPES = {
    "string": "text",
    "Int64": "bigint",
    "Double": "double precision",
    "Boolean": "boolean",
    "DateTime": "timestamptz",
}

## @brief Default schema (namespace) the tables are created in.
DEFAULT_SCHEMA = "t1ote"

## @brief Rows per `INSERT` statement in the `.sql` script.
INSERT_BATCH = 500


## @brief One table to (re)write.
@dataclass
class Table:
    ## Table name.
    name: str
    ## `(column, Power BI type)` pairs, in order.
    columns: list[tuple[str, str]]
    ## Column names forming the primary key (empty for none).
    key: tuple[str, ...] = ()
    ## Columns to index (one index each).
    indexes: tuple[str, ...] = ()
    ## SQL run after the table is loaded (views).
    after: list[str] = field(default_factory=list)


## @brief Quote an identifier (table or column name; spaces and capitals are kept).
def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


## @brief Render a Python value as a SQL literal (used only in the `.sql` script).
def sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value) if value == value and abs(value) != float("inf") else "NULL"
    return "'" + str(value).replace("\x00", "").replace("'", "''") + "'"


## @brief The `assets` table for the selected columns (indexed on `asset_id`; not unique, since two targets may list one device).
def assets_table(columns: list[hx.Column], name: str = "assets") -> Table:
    return Table(name, [(c.name, c.dtype) for c in columns], indexes=("asset_id",))


## @brief `"schema"."table"`.
def qualified(schema: str, name: str) -> str:
    return f"{quote_ident(schema)}.{quote_ident(name)}"


## @brief The statements that create the table, add any missing columns and index it.
def ddl(schema: str, t: Table) -> list[str]:
    q = qualified(schema, t.name)
    cols = [f"{quote_ident(n)} {PG_TYPES.get(k, 'text')}" for n, k in t.columns]
    if t.key:
        cols.append("PRIMARY KEY (" + ", ".join(quote_ident(k) for k in t.key) + ")")
    out = [f"CREATE TABLE IF NOT EXISTS {q} (\n  " + ",\n  ".join(cols) + "\n)"]
    for n, k in t.columns:
        out.append(f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS {quote_ident(n)} {PG_TYPES.get(k, 'text')}")
    for c in t.indexes:
        suffix = re.sub(r"\W+", "_", c).strip("_").lower()
        out.append(f"CREATE INDEX IF NOT EXISTS {quote_ident(t.name + '_' + suffix + '_idx')} ON {q} ({quote_ident(c)})")
    return out


## @brief `INSERT` statements (batched) for the `.sql` script.
def insert_statements(schema: str, t: Table, rows: Iterable[dict[str, Any]]) -> Iterable[str]:
    q = qualified(schema, t.name)
    head = f"INSERT INTO {q} (" + ", ".join(quote_ident(n) for n, _ in t.columns) + ") VALUES\n"
    batch: list[str] = []
    for r in rows:
        batch.append("(" + ", ".join(sql_literal(r.get(n)) for n, _ in t.columns) + ")")
        if len(batch) >= INSERT_BATCH:
            yield head + ",\n".join(batch)
            batch = []
    if batch:
        yield head + ",\n".join(batch)


## @brief The findings view that counts each CVE once per host and product family.
#  @details Fragments of one product (many Visual C++ pieces) share `cpe_product`, so this view
#  gives the de-duplicated picture; `software_count` says how many installed pieces carry the CVE.
def exposure_view(schema: str) -> str:
    f = qualified(schema, "sbom_findings")
    return (
        f"CREATE OR REPLACE VIEW {qualified(schema, 'sbom_exposure')} AS\n"
        f"SELECT asset_id, site, asset_name, cpe_product, cve_id, max(cvss_score) AS cvss_score,\n"
        f"       bool_or(kev) AS kev, count(*) AS software_count\n"
        f"FROM {f}\nGROUP BY asset_id, site, asset_name, cpe_product, cve_id"
    )


## @brief Where the output goes. Create with `open_sink()`.
class SqlSink:
    ## @param schema Schema name for all tables.
    #  @param conn An open `psycopg` connection, or `None` (script only).
    #  @param script Path of the `.sql` file to write, or `None`.
    def __init__(self, schema: str, conn: Any, script: Path | None) -> None:
        self.schema = schema
        self.conn = conn
        self.script = script
        self._done: list[str] = []      # statements already committed
        self._pending: list[str] = []   # statements since the last checkpoint
        self.tables: list[str] = []

    ## @brief Replace one table's contents with `rows`.
    #  @return Number of rows written.
    def replace_table(self, t: Table, rows: list[dict[str, Any]]) -> int:
        q = qualified(self.schema, t.name)
        stmts = ddl(self.schema, t) + [f"TRUNCATE {q}"]
        if self.conn is not None:
            with self.conn.cursor() as cur:
                for s in stmts:
                    cur.execute(s)
                cols = ", ".join(quote_ident(n) for n, _ in t.columns)
                with cur.copy(f"COPY {q} ({cols}) FROM STDIN") as cp:
                    for r in rows:
                        cp.write_row([v.replace("\x00", "") if isinstance(v, str) else v for v in (r.get(n) for n, _ in t.columns)])
                for s in t.after:
                    cur.execute(s)
        if self.script is not None:
            self._pending.extend(stmts)
            self._pending.extend(insert_statements(self.schema, t, rows))
            self._pending.extend(t.after)
        self.tables.append(t.name)
        return len(rows)

    ## @brief Commit what has been written so far (the `run` command does this after the assets).
    def checkpoint(self) -> None:
        if self.conn is not None:
            self.conn.commit()
        self._done.extend(self._pending)
        self._pending = []

    ## @brief Commit (or roll back) and write the script. Safe to call twice.
    #  @param ok False after a failure: uncommitted work is rolled back and left out of the script.
    def finish(self, ok: bool) -> None:
        if self.conn is not None:
            try:
                self.conn.commit() if ok else self.conn.rollback()
            finally:
                self.conn.close()
                self.conn = None
        if ok:
            self._done.extend(self._pending)
        self._pending = []
        if self.script is not None and self._done:
            body = ";\n\n".join(self._done) + ";\n"
            header = (
                "-- Tenable OT export: replaces the contents of the tables below.\n"
                "-- Load with: psql -v ON_ERROR_STOP=1 -f <this file>\n"
                "BEGIN;\nSET standard_conforming_strings = on;\nSET client_min_messages = warning;\n"
                f"CREATE SCHEMA IF NOT EXISTS {quote_ident(self.schema)};\n\n"
            )
            self.script.parent.mkdir(parents=True, exist_ok=True)
            self.script.write_text(header + body + "\nCOMMIT;\n", encoding="utf-8")
            log(f"SQL script written to {self.script}")
            self.script = None


## @brief Add the database options to a command's output group.
def add_db_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("PostgreSQL (optional)")
    g.add_argument("--db", action="store_true", help="Also replace the tables in a PostgreSQL database (needs `pip install \"psycopg[binary]\"`; connection from --db-url, T1OTE_DB_URL or the standard PG* variables).")
    g.add_argument("--db-url", metavar="URL", help="PostgreSQL connection string (env T1OTE_DB_URL). Avoid a password here; prefer PGPASSWORD or ~/.pgpass.")
    g.add_argument("--db-schema", metavar="NAME", help=f"Schema for the tables (env T1OTE_DB_SCHEMA; default {DEFAULT_SCHEMA}); created if missing.")
    g.add_argument("--sql-out", metavar="FILE", help="Also write the same tables as a .sql script you can review and load with psql.")


## @brief Validate a schema name.
def _schema_name(args: argparse.Namespace) -> str:
    name = (getattr(args, "db_schema", None) or os.environ.get("T1OTE_DB_SCHEMA", "") or DEFAULT_SCHEMA).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", name):
        raise ExportError(f"Schema name {name!r} must be letters, digits and underscores, starting with a letter or underscore.")
    return name


## @brief Open the output the command line asks for, or return `None`.
#  @details Connects (and creates the schema) up front so a bad connection fails before a long NVD run.
def open_sink(args: argparse.Namespace) -> SqlSink | None:
    use_db = bool(getattr(args, "db", False))
    script = getattr(args, "sql_out", None)
    if getattr(args, "dry_run", False) or not (use_db or script):
        return None
    schema = _schema_name(args)
    conn = None
    if use_db:
        try:
            import psycopg  # type: ignore[import-not-found]
        except ImportError as e:
            raise ExportError("--db needs the PostgreSQL driver: pip install \"psycopg[binary]\"") from e
        url = getattr(args, "db_url", None) or os.environ.get("T1OTE_DB_URL", "")
        try:
            conn = psycopg.connect(url, connect_timeout=15)
            with conn.cursor() as cur:
                cur.execute("SET client_min_messages = warning")   # "already exists, skipping" notices are noise
                cur.execute(f"CREATE SCHEMA IF NOT EXISTS {quote_ident(schema)}")
            conn.commit()
            info = conn.info
            log(f"Connected to PostgreSQL {info.host or 'local socket'}:{info.port}/{info.dbname} as {info.user}; schema {schema!r}.")
        except Exception as e:  # driver errors are not ours to enumerate; show the message without the password
            raise ExportError(f"Could not connect to PostgreSQL: {str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__}") from e
    return SqlSink(schema, conn, Path(script) if script else None)
