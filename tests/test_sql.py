"""@file tests/test_sql.py
@brief Offline tests for the PostgreSQL output (t1ote_sql.py): SQL text, escaping, replace semantics.

No database is needed: a recording stand-in for the driver's connection checks what would be run.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import t1ote_core as hx  # noqa: E402
import t1ote_sql as sq  # noqa: E402


class FakeCopy:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def write_row(self, row):
        self.log.append(("row", list(row)))


class FakeCursor:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql):
        self.log.append(("sql", sql))

    def copy(self, sql):
        self.log.append(("copy", sql))
        return FakeCopy(self.log)


class FakeConn:
    def __init__(self):
        self.log = []
        self.closed = False

    def cursor(self):
        return FakeCursor(self.log)

    def commit(self):
        self.log.append(("commit", None))

    def rollback(self):
        self.log.append(("rollback", None))

    def close(self):
        self.closed = True


TABLE = sq.Table("things", [("id", "string"), ("n", "Int64"), ("Cost Centre", "string"), ("ok", "Boolean"), ("exported_at", "DateTime")],
                 key=("id",), indexes=("n",))
ROWS = [{"id": "a'b", "n": 3, "Cost Centre": "x\ny", "ok": True, "exported_at": "2026-01-01T00:00:00Z"},
        {"id": "c", "n": None, "Cost Centre": "", "ok": False, "exported_at": "2026-01-01T00:00:00Z"}]


class SqlTextTests(unittest.TestCase):
    def test_identifiers_are_quoted_and_types_mapped(self):
        text = "\n".join(sq.ddl("t1ote", TABLE))
        self.assertIn('CREATE TABLE IF NOT EXISTS "t1ote"."things"', text)
        self.assertIn('"Cost Centre" text', text)
        self.assertIn('"n" bigint', text)
        self.assertIn('"exported_at" timestamptz', text)
        self.assertIn('PRIMARY KEY ("id")', text)
        self.assertIn('ADD COLUMN IF NOT EXISTS "Cost Centre" text', text)          # new columns are added, never dropped
        self.assertIn('CREATE INDEX IF NOT EXISTS "things_n_idx"', text)
        self.assertEqual(sq.quote_ident('a"b'), '"a""b"')

    def test_literals(self):
        self.assertEqual(sq.sql_literal("it's"), "'it''s'")
        self.assertEqual(sq.sql_literal(None), "NULL")
        self.assertEqual((sq.sql_literal(True), sq.sql_literal(False), sq.sql_literal(3), sq.sql_literal(1.5)), ("true", "false", "3", "1.5"))
        self.assertEqual(sq.sql_literal("a\x00b"), "'ab'")
        self.assertEqual(sq.sql_literal(float("nan")), "NULL")
        self.assertEqual(sq.sql_literal("; DROP TABLE x; --"), "'; DROP TABLE x; --'")

    def test_inserts_are_batched(self):
        rows = [{"id": str(i), "n": i} for i in range(sq.INSERT_BATCH + 1)]
        stmts = list(sq.insert_statements("s", TABLE, rows))
        self.assertEqual(len(stmts), 2)
        self.assertTrue(stmts[0].startswith('INSERT INTO "s"."things" ("id", "n", "Cost Centre", "ok", "exported_at") VALUES'))

    def test_assets_table_follows_the_selected_columns(self):
        cols = [hx.Column("asset_id", ()), hx.Column("slot", ("slot",), dtype="Int64")]
        t = sq.assets_table(cols)
        self.assertEqual(t.columns, [("asset_id", "string"), ("slot", "Int64")])
        self.assertEqual(t.key, ())


class SinkTests(unittest.TestCase):
    def test_database_write_truncates_then_copies_in_one_transaction(self):
        conn = FakeConn()
        sink = sq.SqlSink("t1ote", conn, None)
        sink.replace_table(TABLE, ROWS)
        sink.finish(True)
        kinds = [k for k, _ in conn.log]
        self.assertLess(kinds.index("sql"), kinds.index("copy"))
        self.assertTrue(any(k == "sql" and v.startswith('TRUNCATE "t1ote"."things"') for k, v in conn.log))
        rows = [v for k, v in conn.log if k == "row"]
        self.assertEqual(rows[0], ["a'b", 3, "x\ny", True, "2026-01-01T00:00:00Z"])    # parameters/COPY data, not pasted into SQL
        self.assertEqual(rows[1][1], None)
        self.assertEqual(conn.log[-1], ("commit", None))
        self.assertTrue(conn.closed)

    def test_failure_rolls_back_and_writes_no_script(self):
        conn = FakeConn()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "out.sql"
            sink = sq.SqlSink("t1ote", conn, path)
            sink.replace_table(TABLE, ROWS)
            sink.finish(False)
            self.assertEqual(conn.log[-1], ("rollback", None))
            self.assertFalse(path.exists())

    def test_checkpoint_keeps_the_first_part_when_a_later_part_fails(self):
        conn = FakeConn()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "out.sql"
            sink = sq.SqlSink("t1ote", conn, path)
            sink.replace_table(TABLE, ROWS)
            sink.checkpoint()
            sink.replace_table(sq.Table("later", [("a", "string")]), [{"a": "1"}])
            sink.finish(False)
            text = path.read_text()
            self.assertIn('"things"', text)
            self.assertNotIn('"later"', text)
            self.assertIn(("commit", None), conn.log)

    def test_script_is_one_transaction_and_loadable_text(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "sub" / "out.sql"
            sink = sq.SqlSink("my_schema", None, path)
            self.assertEqual(sink.replace_table(TABLE, ROWS), 2)
            sink.finish(True)
            text = path.read_text()
            self.assertTrue(text.startswith("-- Tenable OT export"))
            self.assertIn("BEGIN;", text)
            self.assertTrue(text.rstrip().endswith("COMMIT;"))
            self.assertIn('CREATE SCHEMA IF NOT EXISTS "my_schema";', text)
            self.assertIn("'a''b'", text)
            self.assertLess(text.index("TRUNCATE"), text.index("INSERT INTO"))

    def test_open_sink_is_none_without_options_or_on_dry_run(self):
        import argparse
        self.assertIsNone(sq.open_sink(argparse.Namespace(db=False, sql_out=None, dry_run=False)))
        self.assertIsNone(sq.open_sink(argparse.Namespace(db=True, sql_out="x.sql", dry_run=True)))

    def test_bad_schema_name_is_rejected(self):
        import argparse
        with self.assertRaises(hx.ExportError):
            sq.open_sink(argparse.Namespace(db=False, sql_out="x.sql", dry_run=False, db_schema='x"; drop'))

    def test_exposure_view_counts_each_cve_once_per_product_family(self):
        v = sq.exposure_view("s")
        self.assertIn('"s"."sbom_findings"', v)
        self.assertIn("GROUP BY asset_id, site, asset_name, cpe_product, cve_id", v)


if __name__ == "__main__":
    unittest.main()
