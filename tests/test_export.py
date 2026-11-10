# SPDX-License-Identifier: Apache-2.0
"""@file tests/test_export.py
@brief Offline tests for the shared Tenable client and `t1ote_export_assets.py` commands.

Uses the same fake Tenable / Power BI server as test_sbom.py. No network or
credentials are needed:

    python -m unittest discover -s tests -v
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
from test_sbom import SITE, FakeWorld, _host  # noqa: E402  (only the fake server; not its TestCases)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.outdir = str(Path(self.tmp.name) / "out")
        token = Path(self.tmp.name) / "token.json"
        token.write_text(json.dumps({"refresh_token": "r1"}))
        env = {
            "TENABLE_URL": "https://em.example", "TENABLE_API_KEY": "key-one", "TENABLE_SITE": "", "TENABLE_MODE": "",
            "TENABLE_TLS_VERIFY": "1", "AZURE_TENANT_ID": "tenant", "AZURE_CLIENT_ID": "client",
            "POWERBI_WORKSPACE_ID": "ws1", "TOKEN_CACHE_FILE": str(token), "POWERBI_DATASET_ID": "ds-1",
            "POWERBI_DATASET_NAME": "", "POWERBI_TABLE_NAME": "",
        }
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)

    def world(self, **kw):
        hosts = [_host(1, []), _host(2, [])]
        w = FakeWorld(hosts, **kw)
        m = mock.patch.object(hx, "make_client", lambda verify=True, timeout=30.0: httpx.Client(transport=httpx.MockTransport(w)))
        m.start()
        self.addCleanup(m.stop)
        return w

    def run_cli(self, *argv):
        empty_env = Path(self.tmp.name) / "empty.env"
        empty_env.write_text("")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["--env-file", str(empty_env), *argv])
        return code, out.getvalue(), err.getvalue()

    def write_config(self, text):
        path = Path(self.tmp.name) / "targets.ini"
        path.write_text(text)
        path.chmod(0o600)
        return str(path)

    def test_export_to_a_standalone_icp_needs_no_flag(self):
        w = self.world(standalone_icp=True)
        code, out, err = self.run_cli("assets", "--powerbi", "--out-dir", self.outdir)
        self.assertEqual(code, 0, err)
        self.assertEqual(set(w.graphql_paths), {"/graphql"})
        self.assertIn("2 asset(s) written", out)
        rows = [r for m, path, q, h, b in w.pbi_requests if m == "POST" for r in b["rows"]]
        self.assertEqual({r["site"] for r in rows}, {"em.example"})      # the host name labels ICP data

    def test_export_from_an_enterprise_manager_uses_the_named_site(self):
        w = self.world()
        w.sites = [("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Sydney"), (SITE, "London")]
        self.assertEqual(self.run_cli("assets", "--dry-run")[0], 1)       # several sites, none chosen
        code, out, err = self.run_cli("assets", "--dry-run", "--site", "London")
        self.assertEqual(code, 0, err)
        self.assertIn(f"/{SITE}/graphql", set(w.graphql_paths))

    def test_export_over_several_targets_clears_the_table_once_and_pushes_everything(self):
        w = self.world(standalone_icp=True)
        w.hosts_by_host = {"london.example": [_host(1, [])], "sydney.example": [_host(2, []), _host(3, [])]}
        cfg = self.write_config(
            "[london]\nurl = https://london.example\napi_key = k1\n[sydney]\nurl = https://sydney.example\napi_key = k2\n"
        )
        code, out, err = self.run_cli("assets", "--powerbi", "--out-dir", self.outdir, "--config", cfg)
        self.assertEqual(code, 0, err)
        calls = [m for m, path, q, h, b in w.pbi_requests]
        self.assertEqual(calls, ["GET", "DELETE", "POST"])                # schema check, one clear, then one push of all rows
        rows = w.pbi_requests[2][4]["rows"]
        self.assertEqual(sorted((r["site"], r["name"]) for r in rows), [("london", "WIN-1"), ("sydney", "WIN-2"), ("sydney", "WIN-3")])
        self.assertIn("3 asset(s)", out)

    def test_limit_applies_per_site(self):
        w = self.world(standalone_icp=True)
        w.hosts_by_host = {"a.example": [_host(1, []), _host(2, [])], "b.example": [_host(3, []), _host(4, [])]}
        cfg = self.write_config("[a]\nurl = https://a.example\napi_key = k\n[b]\nurl = https://b.example\napi_key = k\n")
        code, out, err = self.run_cli("assets", "--dry-run", "--config", cfg, "--limit", "1")
        self.assertEqual(code, 0, err)
        self.assertIn("[dry run] 2 asset row(s)", out)

    def test_sites_command_describes_each_target(self):
        w = self.world()
        code, out, err = self.run_cli("sites")
        self.assertEqual(code, 0, err)
        self.assertIn("Enterprise Manager, 1 site(s):", out)
        self.assertIn("London", out)
        self.assertNotIn(SITE, out)                                       # people pick sites by name, never by id
        w.standalone_icp = True
        code, out, err = self.run_cli("sites")
        self.assertIn("standalone ICP (no sites", out)

    def test_assets_without_powerbi_writes_only_a_csv(self):
        w = self.world(standalone_icp=True)
        code, out, err = self.run_cli("assets", "--out-dir", self.outdir)
        self.assertEqual(code, 0, err)
        self.assertEqual(w.pbi_requests, [])                              # Power BI is opt-in on every command
        files = list(Path(self.outdir).glob("assets_*.csv"))
        self.assertEqual(len(files), 1)
        lines = files[0].read_text().splitlines()
        self.assertEqual(lines[0].split(",")[:2], ["asset_id", "site"])
        self.assertIn("firmware_version", lines[0])                       # every column by default
        self.assertEqual(len(lines), 3)                                   # header + 2 assets

    def test_assets_csv_neutralises_spreadsheet_formulas(self):
        w = self.world(standalone_icp=True)
        w.hosts[0]["name"] = "=cmd|calc"
        self.run_cli("assets", "--out-dir", self.outdir)
        self.assertIn("'=cmd|calc", next(Path(self.outdir).glob("assets_*.csv")).read_text())

    def test_run_refreshes_assets_then_software_and_findings(self):
        w = self.world(standalone_icp=True)
        code, out, err = self.run_cli("run", "--powerbi", "--out-dir", self.outdir, "--cache-dir", str(Path(self.tmp.name) / "c"))
        self.assertEqual(code, 0, err)
        tables = [p.rsplit("/", 2)[-2] for m, p, q, h, b in w.pbi_requests if m == "DELETE"]   # each table is cleared, then filled
        self.assertEqual(tables, ["assets", "sbom_software", "sbom_findings"])
        self.assertTrue(list(Path(self.outdir).glob("assets_*.csv")))
        self.assertTrue(list(Path(self.outdir).glob("sbom_cves_*.csv")))

    def test_run_dry_run_touches_nothing(self):
        w = self.world(standalone_icp=True)
        code, out, err = self.run_cli("run", "--dry-run", "--powerbi", "--out-dir", self.outdir)
        self.assertEqual(code, 0, err)
        self.assertEqual(w.pbi_requests, [])
        self.assertFalse(Path(self.outdir).exists())
        self.assertIn("[dry run]", out)

    def test_run_stops_before_the_nvd_run_if_assets_fail(self):
        w = self.world(standalone_icp=True)
        w.pbi_status = 403
        code, out, err = self.run_cli("run", "--powerbi", "--out-dir", self.outdir)
        self.assertEqual(code, 1)
        self.assertEqual(w.nvd_requests, [])

    def test_the_old_script_commands_are_gone(self):
        for cmd in ("export", "scan"):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                cli.build_parser().parse_args([cmd])

    def test_blank_powerbi_settings_fall_back_to_their_defaults(self):
        cfg = hx.PowerBIConfig.from_env(need_dataset=False)
        self.assertEqual((cfg.table_name, cfg.dataset_name, cfg.token_cache.name),
                         ("assets", "Tenable OT Asset Export", "token.json"))
        with mock.patch.dict(os.environ, {"TOKEN_CACHE_FILE": ""}):
            self.assertEqual(hx.PowerBIConfig.from_env(need_dataset=False).token_cache.name, ".powerbi_token.json")

    def test_the_shipped_example_config_parses_cleanly(self):
        example = Path(__file__).resolve().parent.parent / "targets.example.ini"
        with mock.patch.dict(os.environ, {"LONDON_API_KEY": "k-london", "EM_API_KEY": "k-em"}):
            targets = hx.load_config_file(str(example))
        by_name = {t.name: t for t in targets}
        self.assertEqual(list(by_name), ["london", "sydney", "corporate-em"])
        self.assertEqual(by_name["london"].api_key, "k-london")
        self.assertEqual(by_name["sydney"].api_key, "paste-the-key-here")      # no trailing comment text
        self.assertEqual((by_name["corporate-em"].site, by_name["corporate-em"].url), ("Head Office", "https://em.example.com"))
        self.assertTrue(all(t.mode == "auto" and t.tls_verify for t in targets))

    def test_invalid_mode_is_rejected(self):
        self.world()
        with mock.patch.dict(os.environ, {"TENABLE_MODE": "both"}):
            code, out, err = self.run_cli("sites")
        self.assertEqual(code, 1)
        self.assertIn("TENABLE_MODE", err)


if __name__ == "__main__":
    unittest.main()
