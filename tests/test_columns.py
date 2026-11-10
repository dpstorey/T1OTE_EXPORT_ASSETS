# SPDX-License-Identifier: Apache-2.0
"""@file tests/test_columns.py
@brief Offline tests for column selection (`--export-columns`, `--export-all-columns`, `columns`).

Runs against a fake Tenable whose schema is modelled on the real Asset type. No network.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import t1ote_core as hx  # noqa: E402
import t1ote_export_assets as cli  # noqa: E402
from test_sbom import FakeWorld  # noqa: E402


def _t(name, wrap_list=False, kind="SCALAR"):
    leaf = {"kind": kind, "name": name, "ofType": None}
    inner = {"kind": "LIST", "name": None, "ofType": {"kind": "NON_NULL", "name": None, "ofType": leaf}} if wrap_list else leaf
    return {"kind": "NON_NULL", "name": None, "ofType": inner}


def schema_fields(missing=(), extra_custom=0):
    scalars = ["id", "name", "type", "superType", "category", "vendor", "family", "model", "os", "firmwareVersion",
               "serial", "purdueLevel", "location", "description", "runStatus", "extendedRunStatus", "runStatusTime",
               "hardwareState", "lifecycleStatus", "discontinuedDate", "replacementProduct", "firstSeen", "lastSeen",
               "lastHit", "lastSnapshot", "lastUpdate", "criticality", "newFancyField"]
    scalars += [f"customField{i}" for i in range(1, 11 + extra_custom)]
    f = {n: _t("String") for n in scalars}
    f.update({"slot": _t("Int"), "hidden": _t("Boolean"), "ratio": _t("Float")})
    f.update({n: _t("Thing", True, "OBJECT") for n in ("ips", "macs", "subnets", "tags", "segments", "sources")})
    f.update({"risk": _t("Risk", kind="OBJECT"), "backplane": _t("Backplane", kind="OBJECT"),
              "details": _t("Details", kind="OBJECT"), "layout": _t("Layout", kind="OBJECT")})
    for m in missing:
        f.pop(m, None)
    return [{"name": k, "type": v} for k, v in f.items()]


NODE = {
    "id": "a1", "name": "PLC-1", "vendor": "Siemens", "model": "S7", "criticality": "HighCriticality",
    "ips": {"nodes": ["10.0.0.1", "10.0.0.2"]}, "macs": {"nodes": ["aa:bb"]}, "lastSeen": "2026-01-01T00:00:00Z",
    "risk": {"totalRisk": 7.5}, "slot": 3, "hidden": False, "os": None,
    "segments": {"nodes": [{"name": "Cell A", "id": "s1"}, {"name": "Cell B", "id": "s2"}]},
    "backplane": {"id": "bp1", "name": "Rack 1"}, "newFancyField": "x",
}


class SchemaWorld(FakeWorld):
    def __init__(self, *a, missing=(), introspection=True, extra_custom=0, custom=None, **kw):
        super().__init__(*a, **kw)
        self.missing, self.introspection, self.extra_custom = missing, introspection, extra_custom
        self.custom = custom   # list of customFields answers, or None = the server has no such query
        self.queries = []
        self.pbi_tables = None   # what GET .../tables answers

    def __call__(self, request):
        url = request.url
        if url.host == "api.powerbi.com" and request.method == "GET" and url.path.endswith("/tables"):
            self.pbi_requests.append(("GET", url.path, "", {}, None))
            return httpx.Response(200, json={"value": self.pbi_tables or []})
        if url.host not in ("api.powerbi.com", "login.microsoftonline.com", "services.nvd.nist.gov"):
            body = json.loads(request.content)
            self.queries.append(body["query"])
            if "customFields" in body["query"]:
                if self.custom is None:
                    return httpx.Response(200, json={"errors": [{"message": 'Cannot query field "customFields"'}]})
                return httpx.Response(200, json={"data": {"customFields": self.custom}})
            if "__type" in body["query"]:
                if not self.introspection:
                    return httpx.Response(200, json={"errors": [{"message": "introspection disabled"}]})
                return httpx.Response(200, json={"data": {"__type": {"fields": schema_fields(self.missing, self.extra_custom)}}})
        return super().__call__(request)


class ColumnTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.outdir = str(Path(self.tmp.name) / "out")
        token = Path(self.tmp.name) / "token.json"
        token.write_text(json.dumps({"refresh_token": "r1"}))
        env = {
            "TENABLE_URL": "https://em.example", "TENABLE_API_KEY": "k", "TENABLE_SITE": "", "TENABLE_MODE": "",
            "TENABLE_TLS_VERIFY": "1", "AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "POWERBI_WORKSPACE_ID": "ws1",
            "TOKEN_CACHE_FILE": str(token), "POWERBI_DATASET_ID": "ds-1", "POWERBI_DATASET_NAME": "",
            "POWERBI_TABLE_NAME": "", "TENABLE_EXPORT_COLUMNS": "",
        }
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)

    def world(self, **kw):
        w = SchemaWorld([dict(NODE)], **kw)
        m = mock.patch.object(hx, "make_client", lambda verify=True, timeout=30.0: httpx.Client(transport=httpx.MockTransport(w)))
        m.start()
        self.addCleanup(m.stop)
        return w

    def cli(self, *argv, env=None):
        empty = Path(self.tmp.name) / "empty.env"
        empty.write_text("")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env or {}), redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["--env-file", str(empty), *argv])
        return code, out.getvalue(), err.getvalue()

    def pushed(self, w):
        return [r for m, p, q, h, b in w.pbi_requests if m == "POST" and p.endswith("/rows") for r in b["rows"]]

    # ---- pure -----------------------------------------------------------
    def test_names_match_in_any_spelling_and_fixed_columns_are_added(self):
        cols = hx.resolve_columns(["Last Seen", "vendor", "ip", "lastSeen"])
        self.assertEqual([c.name for c in cols], ["asset_id", "site", "last_seen", "vendor", "ips", "exported_at"])

    def test_unknown_column_suggests_and_heavy_fields_are_refused(self):
        with self.assertRaisesRegex(hx.ExportError, "Did you mean: vendor"):
            hx.resolve_columns(["vendr"])
        with self.assertRaisesRegex(hx.ExportError, "large nested"):
            hx.resolve_columns(["details"])

    def test_all_covers_the_inventory_and_skips_what_the_server_lacks(self):
        self.assertEqual({c.name for c in hx.resolve_columns("all")} - {"site", "exported_at"}, {c.name for c in hx.INVENTORY_COLUMNS})
        fields = {k["name"]: ("String", False) for k in schema_fields(missing=("family", "customField3"))}
        fields.update({"ips": ("X", True), "risk": ("Risk", False)})
        names = {c.name for c in hx.resolve_columns("all", fields)}
        self.assertNotIn("family", names)
        self.assertNotIn("custom_field_3", names)
        with self.assertRaisesRegex(hx.ExportError, "not available"):
            hx.resolve_columns(["family"], fields)

    def test_selection_shares_fields_and_pages_lists(self):
        sel = hx.build_selection(hx.resolve_columns(["segments", "segment_ids", "ips", "total_risk", "backplane_name"]))
        self.assertEqual(sel.count("segments"), 1)
        self.assertIn("segments(first: 50) { nodes { name id } }", sel)
        self.assertIn("ips(first: 50) { nodes }", sel)
        self.assertIn("risk { totalRisk }", sel)
        self.assertIn("backplane { name }", sel)
        self.assertTrue(sel.startswith("id "))

    def test_rows_convert_types_and_tolerate_missing_values(self):
        cols = hx.resolve_columns(["name", "slot", "hidden", "total_risk", "criticality", "ips", "segments", "segment_ids", "os", "backplane_name"])
        r = hx.build_rows([NODE, {"id": "z"}], "S", cols)
        self.assertEqual(r[0]["slot"], 3)
        self.assertIs(r[0]["hidden"], False)
        self.assertEqual((r[0]["total_risk"], r[0]["criticality"]), (7.5, "High"))
        self.assertEqual((r[0]["ips"], r[0]["segments"], r[0]["segment_ids"]), ("10.0.0.1, 10.0.0.2", "Cell A, Cell B", "s1, s2"))
        self.assertEqual((r[0]["os"], r[0]["backplane_name"], r[0]["site"]), ("", "Rack 1", "S"))
        self.assertEqual((r[1]["slot"], r[1]["hidden"], r[1]["total_risk"], r[1]["ips"], r[1]["name"]), (None, None, None, "", ""))

    def test_long_text_is_cut_and_marked(self):
        r = hx.build_rows([{"id": "a", "description": "x" * 40_000}], "S", hx.resolve_columns(["description"]))
        self.assertEqual(len(r[0]["description"]), hx.MAX_TEXT)
        self.assertTrue(r[0]["description"].endswith("[truncated]"))

    def test_rows_follow_the_column_order(self):
        cols = hx.resolve_columns(["ips", "name"])
        r = hx.build_rows([NODE], "S", cols)[0]
        self.assertEqual(list(r), ["asset_id", "site", "ips", "name", "exported_at"])
        self.assertEqual(r["ips"], "10.0.0.1, 10.0.0.2")

    def test_spec_precedence_and_formats(self):
        def spec(*argv, env=""):
            p = cli.build_parser()
            a = p.parse_args(["assets", *argv])
            with mock.patch.dict(os.environ, {"TENABLE_EXPORT_COLUMNS": env}):
                return hx.columns_spec(a)
        self.assertEqual(spec(), "all")
        self.assertEqual(spec(env="name, vendor ,ips"), ["name", "vendor", "ips"])
        self.assertEqual(spec(env='["name","vendor"]'), ["name", "vendor"])
        self.assertEqual(spec(env="ALL"), "all")
        self.assertEqual(spec(env="name, Cost Centre,ips"), ["name", "Cost Centre", "ips"])
        self.assertEqual(spec("--export-columns", "model", env="name"), ["model"])
        self.assertEqual(spec("--export-all-columns", env="name"), "all")
        with self.assertRaisesRegex(hx.ExportError, "not both"):
            spec("--export-all-columns", "--export-columns", "name")

    def test_custom_fields_are_named_after_the_console_and_either_spelling_works(self):
        names = {1: "Cost Centre", 3: "Owner", 4: "name", 5: "9 lives"}
        cols = hx.custom_columns(None, names)
        got = [c.name for c in cols]
        self.assertEqual(got[:5], ["Cost Centre", "custom_field_2", "Owner", "custom_field_4", "9 lives"])  # unnamed and clashing names fall back; case and spaces kept
        self.assertEqual(len(got), 10)
        for token in ("cost_centre", "Cost Centre", "cost centre", "custom_field_1", "customField1"):
            self.assertEqual([c.name for c in hx.resolve_columns([token], None, names)][2:-1], ["Cost Centre"])
        node = {"id": "a", "customField1": "CC-9", "customField3": "Ann"}
        r = hx.build_rows([node], "S", hx.resolve_columns(["owner", "Cost Centre"], None, names))[0]
        self.assertEqual((r["Cost Centre"], r["Owner"]), ("CC-9", "Ann"))

    def test_more_than_ten_custom_fields_follow_the_servers_schema(self):
        w = self.world(extra_custom=2, custom=[{"fieldId": "customField11", "userDefinedName": "Zone Lead", "valueType": "Text"}])
        code, out, err = self.cli("assets", "--dry-run", "--export-all-columns")
        self.assertEqual(code, 0, err)
        self.assertIn("Zone Lead", out)
        self.assertIn("custom_field_12", out)
        q = [x for x in w.queries if "assets(" in x][0]
        self.assertIn("customField11", q)
        self.assertIn("customField12", q)

    def test_console_names_are_used_by_export_columns_and_create_dataset(self):
        w = self.world(custom=[{"fieldId": 2, "userDefinedName": "Cost Centre", "valueType": "Text"},
                               {"fieldId": "customField7", "userDefinedName": "", "valueType": "Text"}])
        code, out, err = self.cli( "columns")
        self.assertEqual(code, 0, err)
        self.assertIn("Cost Centre", out)
        self.assertIn("custom_field_7", out)
        code, out, err = self.cli( "create-dataset", "--export-all-columns")
        cols = [c["name"] for c in w.pbi_requests[0][4]["tables"][0]["columns"]]
        self.assertIn("Cost Centre", cols)
        self.assertNotIn("custom_field_2", cols)

    def test_server_without_the_custom_fields_query_keeps_the_numbered_names(self):
        w = self.world(custom=None)
        code, out, err = self.cli("assets", "--dry-run", "--export-columns", "custom_field_3")
        self.assertEqual(code, 0, err)
        self.assertIn('"custom_field_3"', out)

    # ---- commands ---------------------------------------------------------
    def test_export_with_columns_queries_and_pushes_only_them(self):
        w = self.world()
        code, out, err = self.cli("assets", "--powerbi", "--out-dir", self.outdir, "--export-columns", "name,segments,slot")
        self.assertEqual(code, 0, err)
        q = [x for x in w.queries if "assets(" in x][0]
        self.assertIn("segments(first: 50)", q)
        self.assertNotIn("vendor", q)
        self.assertEqual(list(self.pushed(w)[0]), ["asset_id", "site", "name", "segments", "slot", "exported_at"])

    def test_all_columns_from_the_environment(self):
        w = self.world(missing=("family",))
        code, out, err = self.cli("assets", "--dry-run", env={"TENABLE_EXPORT_COLUMNS": "all"})
        self.assertEqual(code, 0, err)
        self.assertIn("custom_field_10", out)
        self.assertNotIn("family", out.split("First rows:")[1])

    def test_default_export_is_every_inventory_column(self):
        w = self.world()
        self.assertEqual(self.cli("assets", "--powerbi", "--out-dir", self.outdir)[0], 0)
        self.assertEqual(set(self.pushed(w)[0]), {c.name for c in hx.resolve_columns("all")})
        self.assertTrue(any("__type" in q for q in w.queries))

    def test_schema_mismatch_stops_before_clearing_the_table(self):
        w = self.world()
        w.pbi_tables = [{"name": "assets", "columns": [{"name": n} for n in ("asset_id", "site", "name", "exported_at")]}]
        code, out, err = self.cli("assets", "--powerbi", "--out-dir", self.outdir, "--export-columns", "serial")
        self.assertEqual(code, 1)
        self.assertIn("serial", err)
        self.assertIn("create-dataset", err)
        self.assertNotIn("DELETE", [m for m, *_ in w.pbi_requests])

    def test_matching_schema_proceeds(self):
        w = self.world()
        w.pbi_tables = [{"name": "assets", "columns": [{"name": c.name} for c in hx.resolve_columns(["serial"])]}]
        self.assertEqual(self.cli("assets", "--powerbi", "--out-dir", self.outdir, "--export-columns", "serial")[0], 0)

    def test_without_introspection_the_catalogue_is_used(self):
        w = self.world(introspection=False)
        code, out, err = self.cli("assets", "--dry-run", "--export-columns", "name,vendor")
        self.assertEqual(code, 0, err)

    def test_extra_field_from_the_server_can_be_named(self):
        w = self.world()
        code, out, err = self.cli("assets", "--dry-run", "--export-columns", "new_fancy_field")
        self.assertEqual(code, 0, err)
        self.assertIn('"new_fancy_field": "x"', out)

    def test_columns_command_lists_catalogue_extras_and_selection(self):
        w = self.world(missing=("family",))
        code, out, err = self.cli( "columns", "--export-columns", "name,ips")
        self.assertEqual(code, 0, err)
        self.assertIn("firmware_version", out)
        self.assertRegex(out, r"family .*\(not on this server\)")
        self.assertIn("new_fancy_field", out)
        self.assertIn("Selected (5): asset_id, site, name, ips, exported_at", out)
        code, out, err = self.cli( "columns")
        self.assertIn(", all):", out)

    def test_create_dataset_uses_the_selected_columns(self):
        w = self.world()
        code, out, err = self.cli( "create-dataset", "--export-all-columns")
        self.assertEqual(code, 0, err)
        cols = {c["name"]: c["dataType"] for c in w.pbi_requests[0][4]["tables"][0]["columns"]}
        self.assertEqual(cols["slot"], "Int64")
        self.assertEqual(cols["total_risk"], "Double")
        self.assertEqual(cols["hidden"], "Boolean")
        self.assertEqual(cols["exported_at"], "DateTime")
        self.assertIn("custom_field_10", cols)
        self.assertLess(len(cols), 75)                                     # Power BI's per-table column limit

    def test_create_dataset_without_options_has_every_column(self):
        w = self.world()
        code, out, err = self.cli("create-dataset")
        self.assertEqual(code, 0, err)
        names = [c["name"] for c in w.pbi_requests[0][4]["tables"][0]["columns"]]
        self.assertEqual(names, [c.name for c in hx.resolve_columns("all", {k["name"]: ("String", False) for k in schema_fields()})])
        self.assertGreater(len(names), 50)

    def test_sbom_create_dataset_takes_the_same_options(self):
        w = self.world()
        code, out, err = self.cli( "create-dataset", "--export-columns", "name,serial")
        self.assertEqual(code, 0, err)
        tables = {t["name"]: [c["name"] for c in t["columns"]] for t in w.pbi_requests[0][4]["tables"]}
        self.assertEqual(tables["assets"], ["asset_id", "site", "name", "serial", "exported_at"])
        self.assertEqual(set(tables), {"assets", "sbom_software", "sbom_findings"})


if __name__ == "__main__":
    unittest.main()
