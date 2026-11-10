# SPDX-License-Identifier: Apache-2.0
"""@file tests/test_sbom.py
@brief Offline tests for t1ote_sbom.py.

Tenable and the NVD are both answered by one fake `httpx.MockTransport`,
swapped in through `t1ote_core.make_client` (the program's single
HTTP-client factory). No network, credentials or API keys are needed:

    python -m unittest discover -s tests -v
"""

import csv
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import t1ote_core as hx  # noqa: E402
import t1ote_export_assets as cli  # noqa: E402
import t1ote_sbom as sb  # noqa: E402

SITE = "11111111-1111-4111-8111-111111111111"
WIRESHARK_CPE = "cpe:2.3:a:wireshark:wireshark:4.0.5:*:*:*:*:*:*:*"


def _host(i, software):
    """An asset node as the SBOM query returns it."""
    return {
        "id": f"host-{i}",
        "name": f"WIN-{i}",
        "os": "Windows 10",
        "ips": {"nodes": [f"10.0.0.{i}"]},
        "details": {"windows": {"installedSoftware": [
            {"name": n, "version": v, "installDate": "Jan 1 2024"} for n, v in software
        ]}},
    }


def _cve(cve_id, score, kev=False, status="Analyzed", key="cvssMetricV31"):
    cve = {
        "id": cve_id,
        "vulnStatus": status,
        "published": "2024-03-01T10:00:00.000",
        "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": f"Bug {cve_id}"}],
        "metrics": {key: [{"cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}]},
    }
    if kev:
        cve["cisaExploitAdd"] = "2024-04-01"
    return {"cve": cve}


class FakeWorld:
    """Answers Tenable GraphQL and NVD REST calls; records every request."""

    def __init__(self, hosts, nvd=None, reject_os_filter=False, standalone_icp=False):
        self.hosts = hosts
        self.sites = [(SITE, "London")]   # paired sites an Enterprise Manager reports
        self.site_hosts = {}              # site machine id -> hosts, when sites differ
        self.hosts_by_host = {}           # server host name -> hosts, for multi-target tests
        self.icp_hosts = set()            # server host names that behave as standalone ICPs
        self.is_em_field = True           # False: the server does not know the isEm field
        self.auth_fail = False            # True: every GraphQL call answers 401
        self.graphql_calls = []           # (host name, path, X-APIKeys header)
        self.cpe_dictionary = {}          # lower-case keywordSearch -> CPE names the NVD dictionary returns
        self.nvd = nvd or {}  # cpeName -> list of NVD vulnerability objects, or None for 404
        self.reject_os_filter = reject_os_filter
        self.standalone_icp = standalone_icp  # no EM resolvers, no per-site route
        self.graphql_paths = []
        self.full_details = {}  # asset id -> details returned by asset(id) {details}
        self.detail_fetches = []
        self.pbi_requests = []   # (method, path, query, headers, json body)
        self.pbi_status = 200    # set to e.g. 403 to make Power BI refuse writes
        self.nvd_requests = []
        self.graphql_vars = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = urlparse(str(request.url))
        if url.hostname == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        if url.hostname == "api.powerbi.com":
            body = json.loads(request.content) if request.content else None
            self.pbi_requests.append((request.method, url.path, url.query, dict(request.headers), body))
            if self.pbi_status >= 400:
                return httpx.Response(self.pbi_status, text="denied")
            if request.method == "POST" and url.path.endswith("/datasets"):
                return httpx.Response(201, json={"id": "ds-123"})
            return httpx.Response(200, json={})
        if url.hostname == "services.nvd.nist.gov":
            self.nvd_requests.append(request)
            qs = parse_qs(url.query, keep_blank_values=True)
            if "cpes" in url.path:
                names = self.cpe_dictionary.get(qs.get("keywordSearch", [""])[0].lower(), [])
                return httpx.Response(200, json={"products": [{"cpe": {"cpeName": n, "deprecated": False}} for n in names]})
            cpe = qs["cpeName"][0]
            vulns = self.nvd.get(cpe, [])
            if vulns is None:
                return httpx.Response(404, json={})
            return httpx.Response(200, json={"resultsPerPage": len(vulns), "totalResults": len(vulns), "vulnerabilities": vulns})
        body = json.loads(request.content)
        q = body["query"]
        self.graphql_paths.append(url.path)
        self.graphql_calls.append((url.hostname, url.path, request.headers.get("x-apikeys")))
        if self.auth_fail:
            return httpx.Response(401, text="Unauthorized")
        icp = self.standalone_icp or url.hostname in self.icp_hosts
        if icp and url.path != "/graphql":
            return httpx.Response(404, text="404 page not found")
        if "emPairedIcps" in q:
            if icp:
                return httpx.Response(200, json={"errors": [{"message": "404: 404 page not found"}]})
            edges = [{"node": {"site": {"machineId": i, "name": n}}} for i, n in self.sites]
            return httpx.Response(200, json={"data": {"emPairedIcps": {"edges": edges}}})
        if "isEm" in q:
            if not self.is_em_field:
                return httpx.Response(200, json={"errors": [{"message": 'Cannot query field "isEm" on type "Query".'}]})
            if "isEm {" not in q and "isEm{" not in q:   # isEm is an object type, needs a sub-selection
                return httpx.Response(200, json={"errors": [{"message": 'Field "isEm" of type "isEmMachine!" must have a selection of subfields.'}]})
            return httpx.Response(200, json={"data": {"isEm": {"isEm": not icp}}})
        if "__type" in q or "customFields" in q:   # schema questions: not supported, so the built-in catalogue is used
            return httpx.Response(200, json={"errors": [{"message": "introspection disabled"}]})
        if "asset(id" in q:
            aid = body["variables"]["id"]
            self.detail_fetches.append(aid)
            if aid == "boom":
                return httpx.Response(200, json={"errors": [{"message": "details failed"}]})
            return httpx.Response(200, json={"data": {"asset": {"details": self.full_details.get(aid)}}})
        self.graphql_vars.append(body.get("variables") or {})
        flt = (body.get("variables") or {}).get("filter")
        if self.reject_os_filter and flt and "Like" in json.dumps(flt):
            return httpx.Response(200, json={"errors": [{"message": "bad filter"}]})
        size = body["variables"]["pageSize"]
        start = int(body["variables"].get("after") or 0)
        site_prefix = url.path.strip("/").split("/")[0]
        hosts = self.hosts_by_host.get(url.hostname) or self.site_hosts.get(site_prefix) or self.hosts
        page = hosts[start:start + size]
        end = start + len(page)
        return httpx.Response(200, json={"data": {"assets": {
            "totalCount": len(hosts),
            "pageInfo": {"hasNextPage": end < len(hosts), "endCursor": str(end)},
            "nodes": page,
        }}})


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / "out"
        self.cache = Path(self.tmp.name) / "cache"
        env = {"TENABLE_URL": "https://em.example", "TENABLE_API_KEY": "key-one", "TENABLE_SITE": "", "TENABLE_MODE": "", "TENABLE_TLS_VERIFY": "1"}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("NVD_API_KEY", None)
        s = mock.patch.object(time, "sleep")
        self.sleeps = s.start()
        self.addCleanup(s.stop)

    def use(self, world):
        m = mock.patch.object(hx, "make_client", lambda verify=True, timeout=30.0: httpx.Client(transport=httpx.MockTransport(world)))
        m.start()
        self.addCleanup(m.stop)
        return world

    def scan(self, *extra):
        empty_env = Path(self.tmp.name) / "empty.env"
        empty_env.write_text("")
        argv = ["--env-file", str(empty_env), "sbom", "--out-dir", str(self.out), "--cache-dir", str(self.cache), *extra]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def read_csv(self, prefix):
        files = sorted(self.out.glob(prefix + "_*.csv"))
        self.assertEqual(len(files), 1, files)
        with files[0].open(newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))


class PureFunctionTests(unittest.TestCase):
    def test_extract_prefers_raw_list(self):
        d = {"windows": {"installedSoftware": [{"name": " Wireshark ", "version": "4.0.5"}, {"version": "1"}]}}
        self.assertEqual(sb.extract_software(d), [("Wireshark", "4.0.5")])

    def test_extract_falls_back_to_ui_table_and_json_string(self):
        d = {"installedSoftware": {"data": [{"Name": "TightVNC", "Version": "2.8"}]}}
        self.assertEqual(sb.extract_software(d), [("TightVNC", "2.8")])
        self.assertEqual(sb.extract_software(json.dumps(d)), [("TightVNC", "2.8")])

    def test_extract_tolerates_junk(self):
        for junk in (None, "not json", 5, {}, {"windows": {}}, {"cip": {"deviceType": "x"}}):
            self.assertEqual(sb.extract_software(junk), [])

    def test_noise_filter_drops_data_files_not_products(self):
        for noise in ("Rockwell Automation 1769 Controller Module Profiles", "Microsoft .NET Framework 4.5 Multi-Targeting Pack",
                      "Dialight EtherNet/IP Module Profiles", "Schneider Electric BME NOR DTM Library", "Logix Designer SDK",
                      "Update for x64-based Windows Systems (KB5001716)"):
            self.assertTrue(sb.is_noise(noise), noise)
        for product in ("Wireshark 4.0.5 64-bit", "Google Chrome", "TightVNC", "FactoryTalk Linx 6.40.00 (CPR 9 SR 14)"):
            self.assertFalse(sb.is_noise(product), product)

    def test_clean_name_and_version(self):
        self.assertEqual(sb.clean_name("Wireshark 4.0.5 64-bit", "4.0.5"), "Wireshark")
        self.assertEqual(sb.clean_name("Foo (x64) Bar"), "Foo Bar")
        self.assertEqual(sb.clean_version("4.31.00 CPR 9 SR 13.0"), "4.31.00")
        self.assertEqual(sb.clean_version("153.0.8010.53"), "153.0.8010.53")
        self.assertIsNone(sb.clean_version("—"))
        self.assertIsNone(sb.clean_version(""))

    def test_cpe_is_escaped(self):
        self.assertEqual(sb.make_cpe("notepad-plus-plus", "notepad++", "8.1"),
                         r"cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.1:*:*:*:*:*:*:*")

    def test_curated_mapping_and_user_override(self):
        cpe, basis = sb.map_product("Wireshark 4.0.5 64-bit", "4.0.5", [])
        self.assertEqual((cpe, basis), (WIRESHARK_CPE, "curated"))
        cpe, basis = sb.map_product("Wireshark 4.0.5 64-bit", "4.0.5", [(r"^wireshark", "acme", "shark")])
        self.assertEqual((cpe, basis), ("cpe:2.3:a:acme:shark:4.0.5:*:*:*:*:*:*:*", "user_map"))
        self.assertEqual(sb.map_product("Unknown Tool", "1.0", []), (None, ""))
        self.assertEqual(sb.map_product("Wireshark", "n/a", []), (None, ""))

    def test_controlflash_plus_telemetry_is_not_controlflash_plus(self):
        self.assertEqual(sb.map_product("ControlFLASH Plus Telemetry Collector v1.0.0", "1.0.0", []), (None, ""))

    def test_map_file_validation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "m.json"
            p.write_text(json.dumps({"^foo": ["acme", "foo"]}))
            self.assertEqual(sb.load_map_file(str(p)), [("^foo", "acme", "foo")])
            for bad in ("[]", '{"^foo": ["only-one"]}', '{"(": ["a", "b"]}', "nope"):
                p.write_text(bad)
                with self.assertRaises(hx.ExportError):
                    sb.load_map_file(str(p))
        self.assertEqual(sb.load_map_file(None), [])
        with self.assertRaises(hx.ExportError):
            sb.load_map_file("/no/such/file.json")

    def test_parse_cve_prefers_newest_cvss_and_flags_kev(self):
        c = _cve("CVE-1", 7.5, kev=True)["cve"]
        c["metrics"]["cvssMetricV2"] = [{"cvssData": {"baseScore": 4.0}, "baseSeverity": "MEDIUM"}]
        out = sb.parse_cve(c)
        self.assertEqual((out["score"], out["severity"], out["kev"], out["published"]), (7.5, "HIGH", True, "2024-03-01"))
        self.assertEqual(out["description"], "Bug CVE-1")
        v2 = sb.parse_cve(_cve("CVE-2", 5.0, key="cvssMetricV2")["cve"])
        self.assertEqual(v2["score"], 5.0)
        self.assertIsNone(sb.parse_cve(_cve("CVE-3", 9.0, status="Rejected")["cve"]))
        self.assertIsNone(sb.parse_cve({"id": "CVE-4", "metrics": {}})["score"])

    def test_csv_cells_cannot_become_formulas(self):
        self.assertEqual(sb._csv_safe("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(sb._csv_safe("@SUM(1)"), "'@SUM(1)")
        self.assertEqual(sb._csv_safe("Wireshark"), "Wireshark")
        self.assertEqual(sb._csv_safe(7.5), 7.5)

    def test_windows_clause_is_anded_with_other_scope(self):
        self.assertEqual(sb.with_windows_clause(None), sb._WINDOWS_CLAUSE)
        one = {"field": "ips", "op": "Between", "values": ["a", "b"]}
        self.assertEqual(sb.with_windows_clause(one)["expressions"], [one, sb._WINDOWS_CLAUSE])
        both = {"op": "And", "expressions": [one, one]}
        self.assertEqual(len(sb.with_windows_clause(both)["expressions"]), 3)

    def test_vendor_is_read_from_the_name_and_unknown_names_stay_unknown(self):
        self.assertEqual(sb.vendor_hint("Microsoft Access database engine 2016 (English)"), ("Microsoft", "microsoft"))
        self.assertEqual(sb.vendor_hint("Zebra Technologies EtherNet/IP Printer Module Profiles")[0], "Zebra Technologies")
        self.assertEqual(sb.vendor_hint("Visual C++ 2013 Redistributable")[0], "Microsoft")
        for unknown in ("PSx LOKI DTM", "NetmanageServerSoMBasic", "450L Safety Light Curtain"):
            self.assertIsNone(sb.vendor_hint(unknown))

    def test_suggest_pick_needs_the_hinted_vendor_and_prefers_the_longest_product(self):
        cands = [("acme", "sql_server"), ("microsoft", "sql_server"), ("microsoft", "sql_server_compact")]
        self.assertEqual(sb.suggest_pick("Microsoft SQL Server Compact 4.0", "microsoft", cands), ("microsoft", "sql_server_compact", "high"))
        self.assertIsNone(sb.suggest_pick("Acme Widget", "microsoft", [("acme", "widget")]))      # wrong vendor for the hint
        self.assertEqual(sb.suggest_pick("Acme Widget 2", None, [("acme", "widget")]), ("acme", "widget", "medium"))
        self.assertIsNone(sb.suggest_pick("Microsoft Thing", "microsoft", [("microsoft", "x")]))  # too short to trust

    def test_fuzzy_pick_is_strict(self):
        self.assertEqual(sb.fuzzy_pick("Wireshark 4.0.5", [("x", "y"), ("wireshark", "wireshark")]), ("wireshark", "wireshark"))
        self.assertIsNone(sb.fuzzy_pick("Wireshark", [("acme", "tool")]))
        self.assertIsNone(sb.fuzzy_pick("Wireshark", []))


class CacheTests(unittest.TestCase):
    def test_ttl_and_persistence(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "sub" / "c.json"
            c = sb.DiskCache(path)
            c.put("k", {"a": 1})
            c.save()
            self.assertEqual(sb.DiskCache(path).get("k"), {"a": 1})
            self.assertIsNone(sb.DiskCache(path, ttl_days=0).get("k"))  # everything is stale

    def test_corrupt_cache_is_just_cold(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "c.json"
            path.write_text("{not json")
            self.assertIsNone(sb.DiskCache(path).get("k"))


class NvdClientTests(Base):
    def client(self, world, key=""):
        self.use(world)
        return sb.NvdClient(key, sb.DiskCache(None))

    def test_paginates_and_caches(self):
        calls = []

        def handler(request):
            calls.append(str(request.url))
            start = int(parse_qs(urlparse(str(request.url)).query)["startIndex"][0])
            page = [_cve(f"CVE-{start}", 7.0)] if start == 0 else [_cve("CVE-1", 8.0)]
            return httpx.Response(200, json={"resultsPerPage": 1, "totalResults": 2, "vulnerabilities": page})

        self.use(handler)
        nvd = sb.NvdClient("", sb.DiskCache(None))
        cves, known = nvd.cves_for_cpe(WIRESHARK_CPE)
        self.assertTrue(known)
        self.assertEqual([c["id"] for c in cves], ["CVE-0", "CVE-1"])
        self.assertEqual(len(calls), 2)
        self.assertIn("isVulnerable", calls[0])
        nvd.cves_for_cpe(WIRESHARK_CPE)  # served from cache
        self.assertEqual(len(calls), 2)

    def test_progress_and_cache_checkpoint_every_25_requests(self):
        self.use(lambda request: httpx.Response(404, json={}))
        path = Path(self.tmp.name) / "nvd_cache.json"
        nvd = sb.NvdClient("", sb.DiskCache(path), interval=0)
        err = io.StringIO()
        with redirect_stderr(err):
            for i in range(24):
                nvd.cves_for_cpe(f"cpe:2.3:a:v:p:{i}.0:*:*:*:*:*:*:*")
            self.assertFalse(path.exists())            # nothing saved before the 25th request
            self.assertNotIn("NVD:", err.getvalue())
            nvd.cves_for_cpe("cpe:2.3:a:v:p:24.0:*:*:*:*:*:*:*")
            self.assertTrue(path.exists())
            self.assertIn("25 requests made so far", err.getvalue())
            saved = json.loads(path.read_text())
            self.assertGreaterEqual(len(saved), 24)    # earlier lookups survive an interruption
            for i in range(25, 50):
                nvd.cves_for_cpe(f"cpe:2.3:a:v:p:{i}.0:*:*:*:*:*:*:*")
        self.assertIn("50 requests made so far", err.getvalue())

    def test_404_means_unknown_cpe(self):
        nvd = self.client(FakeWorld([], {WIRESHARK_CPE: None}))
        self.assertEqual(nvd.cves_for_cpe(WIRESHARK_CPE), ([], False))

    def test_api_key_header_and_interval(self):
        seen = []
        self.use(lambda r: (seen.append(r.headers.get("apiKey")), httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0}))[1])
        nvd = sb.NvdClient("sekret", sb.DiskCache(None))
        nvd.cves_for_cpe(WIRESHARK_CPE)
        self.assertEqual(seen, ["sekret"])
        self.assertEqual(nvd.interval, sb.NVD_INTERVAL_WITH_KEY)
        self.assertEqual(sb.NvdClient("", sb.DiskCache(None)).interval, sb.NVD_INTERVAL_NO_KEY)

    def test_rate_limit_is_retried_then_succeeds(self):
        answers = [httpx.Response(403), httpx.Response(429), httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})]
        self.use(lambda r: answers.pop(0))
        nvd = sb.NvdClient("", sb.DiskCache(None))
        self.assertEqual(nvd.cves_for_cpe(WIRESHARK_CPE), ([], True))

    def test_persistent_refusal_gives_a_clear_error(self):
        self.use(lambda r: httpx.Response(403))
        with self.assertRaisesRegex(hx.ExportError, "NVD_API_KEY"):
            sb.NvdClient("", sb.DiskCache(None)).cves_for_cpe(WIRESHARK_CPE)

    def test_hard_http_error_is_reported(self):
        self.use(lambda r: httpx.Response(500, text="boom"))
        with self.assertRaisesRegex(hx.ExportError, "HTTP 500"):
            sb.NvdClient("", sb.DiskCache(None)).cves_for_cpe(WIRESHARK_CPE)


class ScanTests(Base):
    def world(self, **kw):
        hosts = [
            _host(1, [("Wireshark 4.0.5 64-bit", "4.0.5"), ("Rockwell Automation 1769 Controller Module Profiles", "30.7"),
                      ("=EVIL() Tool", "1.0")]),
            _host(2, [("Wireshark 4.0.5 64-bit", "4.0.5"), ("Mystery Suite", "2.0")]),
            {"id": "plc-1", "name": "PLC", "os": None, "ips": {"nodes": []}, "details": {"cip": {"deviceType": "x"}}},
        ]
        nvd = {WIRESHARK_CPE: [_cve("CVE-2024-1111", 9.8, kev=True), _cve("CVE-2024-2222", 5.0)]}
        return self.use(FakeWorld(hosts, nvd, **kw))

    def test_end_to_end_report(self):
        w = self.world()
        code, out, err = self.scan()
        self.assertEqual(code, 0, err)
        rows = self.read_csv("sbom_cves")
        # 2 CVEs x 2 hosts, sorted by score descending
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["cve_id"], "CVE-2024-1111")
        self.assertEqual(rows[0]["kev"], "True")
        self.assertEqual({r["asset_name"] for r in rows}, {"WIN-1", "WIN-2"})
        self.assertEqual(rows[0]["match_basis"], "curated")
        self.assertEqual(rows[0]["cpe"], WIRESHARK_CPE)
        # the NVD is asked once per distinct CPE, however many hosts have it
        self.assertEqual(len(w.nvd_requests), 1)
        # JSON mirrors the CSV
        js = json.loads(next(self.out.glob("sbom_cves_*.json")).read_text())
        self.assertEqual(len(js), 4)
        # unmapped list: the unknown product and the formula-injection name (escaped), not the noise
        un = self.read_csv("sbom_unmapped")
        names = {r["product"] for r in un}
        self.assertEqual(names, {"Mystery Suite", "'=EVIL() Tool"})
        self.assertIn("inferred", out)

    def test_suggest_map_proposes_only_what_the_nvd_confirms(self):
        w = self.world()
        w.cpe_dictionary = {
            "microsoft sql server compact 4.0 enu": ["cpe:2.3:a:microsoft:sql_server_compact:4.0:*:*:*:*:*:*:*", "cpe:2.3:a:acme:sql_server:1:*:*:*:*:*:*:*"],
            "microsoft visual c++ 2013 redistributable": ["cpe:2.3:a:microsoft:visual_c\\+\\+_2013:12.0:*:*:*:*:*:*:*"],
        }
        un = self.out.parent / "unmapped.csv"
        un.write_text(
            "product,version,reason,hosts\n"
            "Microsoft SQL Server Compact 4.0 x64 ENU,4.0.5386.0,no CPE mapping,3\n"
            "Microsoft Visual C++ 2013 Redistributable (x64),12.0.30501,no CPE mapping,5\n"
            "Zebra Technologies Widget Tool,1.0,no CPE mapping,1\n"
            "PSx LOKI DTM,3.21.39.0,no CPE mapping,1\n"
            "Wireshark,4.0.5,CPE not in NVD dictionary,2\n"
        )
        out, err = io.StringIO(), io.StringIO()
        empty = Path(self.tmp.name) / "empty.env"
        empty.write_text("")
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["--env-file", str(empty), "suggest-map", str(un), "--out-dir", str(self.out), "--cache-dir", str(self.cache)])
        self.assertEqual(code, 0, err.getvalue())
        review = {r["product"]: r for r in self.read_csv("sbom_mapping_review")}
        self.assertEqual(set(review), {"Microsoft SQL Server Compact 4.0 ENU", "Microsoft Visual C++ 2013 Redistributable", "Zebra Technologies Widget Tool", "PSx LOKI DTM"})
        self.assertEqual((review["Microsoft SQL Server Compact 4.0 ENU"]["status"], review["Microsoft SQL Server Compact 4.0 ENU"]["proposed_product"]), ("suggested", "sql_server_compact"))
        self.assertEqual(review["Microsoft Visual C++ 2013 Redistributable"]["proposed_product"], "visual_c++_2013")   # CPE escapes removed
        self.assertEqual(review["Zebra Technologies Widget Tool"]["status"], "vendor_known_no_nvd_product")
        self.assertEqual(review["PSx LOKI DTM"]["status"], "unknown_vendor")
        # the draft file is a valid --map-file and maps the original product names
        path = next(self.out.glob("sbom_mapping_suggestions_*.json"))
        user_map = sb.load_map_file(str(path))
        self.assertEqual(len(user_map), 2)
        cpe, basis = sb.map_product("Microsoft SQL Server Compact 4.0 x64 ENU", "4.0.5386.0", user_map)
        self.assertEqual((cpe, basis), ("cpe:2.3:a:microsoft:sql_server_compact:4.0.5386.0:*:*:*:*:*:*:*", "user_map"))
        cpe, _ = sb.map_product("Microsoft Visual C++ 2013 Redistributable (x64)", "12.0.30501", user_map)
        self.assertIn(r"visual_c\+\+_2013", cpe)                                          # escaped exactly once
        # only product names reach the NVD
        sent = " ".join(str(r.url) for r in w.nvd_requests)
        self.assertNotIn("hosts", sent)

    def test_map_file_entries_with_leftover_cpe_escapes_are_cleaned(self):
        p = Path(tempfile.mkdtemp()) / "m.json"
        p.write_text(json.dumps({"^microsoft visual c": ["microsoft", "visual_c\\+\\+"], "^x": ["microsoft", "visual_c++"]}))
        user_map = sb.load_map_file(str(p))
        self.assertEqual([v for _, _, v in user_map], ["visual_c++", "visual_c++"])
        cpe, _ = sb.map_product("Microsoft Visual C++ 2008", "9.0.30729", user_map)
        self.assertEqual(cpe.count("\\\\"), 0)                                            # no doubled backslashes
        self.assertIn(r"visual_c\+\+", cpe)

    def test_vendor_file_matches_titles_ignoring_versions_and_formats(self):
        p = Path(tempfile.mkdtemp()) / "v.tsv"
        p.write_text("Title\tVendor\nActiveState ActivePython 2.7.8.10\tActiveState Software\nXip Driver\tSchneider Electric\n")
        v = sb.load_vendor_file(str(p))
        self.assertEqual(v[sb._vendor_key("ActiveState ActivePython", "2.7.8.10")], "ActiveState Software")   # version in title or in the version column
        self.assertEqual(v[sb._vendor_key("Xip Driver X64")], "Schneider Electric")
        csvp = Path(tempfile.mkdtemp()) / "v.csv"
        csvp.write_text("product,Vendor\nClassic Shell,Ivo Beltchev\n")
        self.assertEqual(sb.load_vendor_file(str(csvp)), {"classic shell": "Ivo Beltchev"})
        bad = Path(tempfile.mkdtemp()) / "b.csv"
        bad.write_text("a,b\n1,2\n")
        with self.assertRaises(sb.ExportError):
            sb.load_vendor_file(str(bad))
        self.assertEqual(sb.load_vendor_file(None), {})

    def test_vendor_file_gives_supplier_hints_without_overriding_builtin_prefixes(self):
        v = {"classic shell": "Ivo Beltchev"}
        self.assertEqual(sb.vendor_hint("Classic Shell", v), ("Ivo Beltchev", ""))
        self.assertIsNone(sb.vendor_hint("Classic Shell"))
        self.assertEqual(sb.vendor_hint("Microsoft OneDrive", {"microsoft onedrive": "Someone Else"})[0], "Microsoft")

    def test_vendor_file_becomes_the_cyclonedx_supplier_marked_as_user_supplied(self):
        self.world()
        vf = self.out.parent / "vendors.tsv"
        vf.write_text("Title\tVendor\nMystery Suite\tAcme Corp\n")
        code, out, err = self.scan("--cyclonedx", "--vendor-file", str(vf))
        self.assertEqual(code, 0, err)
        bom = json.loads(next(self.out.glob("sbom_cyclonedx_*.json")).read_text())
        mystery = [c for c in bom["components"] if c["name"] == "Mystery Suite"][0]
        self.assertEqual(mystery["supplier"], {"name": "Acme Corp"})
        self.assertEqual(mystery["manufacturer"], {"name": "Acme Corp"})
        self.assertIn({"name": "t1ote:supplier_basis", "value": "vendor_file"}, mystery["properties"])
        others = [c for c in bom["components"] if c["type"] == "application" and c["name"] != "Mystery Suite"]
        self.assertTrue(all("supplier" not in c for c in others))                           # nothing is invented for the rest

    def test_vendor_file_is_picked_up_by_default_and_can_be_switched_off(self):
        import os, tempfile
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                env = {k: v for k, v in os.environ.items() if k != "TENABLE_VENDOR_FILE"}
                with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(sb, "__file__", str(Path(d) / "x" / "t1ote_sbom.py")):
                    self.assertIsNone(sb.find_vendor_file(None))
                    Path(d, "vendors.tsv").write_text("Title\tVendor\nA\tB\n")
                    self.assertEqual(Path(sb.find_vendor_file(None)).name, "vendors.tsv")
                    self.assertIsNone(sb.find_vendor_file("none"))
                    self.assertEqual(sb.find_vendor_file("mine.tsv"), "mine.tsv")
            finally:
                os.chdir(old)

    def test_suggest_map_dry_run_makes_no_nvd_requests(self):
        w = self.world()
        un = self.out.parent / "unmapped.csv"
        un.write_text("product,version,reason,hosts\nMicrosoft OneDrive,1.0,no CPE mapping,1\n")
        empty = Path(self.tmp.name) / "empty.env"
        empty.write_text("")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main(["--env-file", str(empty), "suggest-map", str(un), "--dry-run", "--out-dir", str(self.out)])
        self.assertEqual(code, 0)
        self.assertEqual(w.nvd_requests, [])
        self.assertEqual(self.read_csv("sbom_mapping_review")[0]["vendor_hint"], "Microsoft")
        self.assertFalse(list(self.out.glob("sbom_mapping_suggestions_*.json")))

    def test_cyclonedx_is_written_only_when_asked(self):
        self.world()
        self.scan()
        self.assertFalse(list(self.out.glob("sbom_cyclonedx_*.json")))

    def test_cyclonedx_bom_links_hosts_software_and_vulnerabilities(self):
        self.world()
        code, out, err = self.scan("--cyclonedx")
        self.assertEqual(code, 0, err)
        self.assertIn("sbom_cyclonedx_", out)
        bom = json.loads(next(self.out.glob("sbom_cyclonedx_*.json")).read_text())
        self.assertEqual((bom["bomFormat"], bom["specVersion"], bom["version"]), ("CycloneDX", "1.6", 1))
        self.assertRegex(bom["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
        comps = {c["bom-ref"]: c for c in bom["components"]}
        self.assertEqual(len(comps), len({c["bom-ref"] for c in bom["components"]}))     # refs are unique
        devices = [c for c in comps.values() if c["type"] == "device"]
        apps = [c for c in comps.values() if c["type"] == "application"]
        self.assertEqual(sorted(d["name"] for d in devices), ["WIN-1", "WIN-2"])
        wire = [a for a in apps if a.get("cpe") == WIRESHARK_CPE]
        self.assertEqual(len(wire), 1)                                                   # one component, two hosts
        root = bom["metadata"]["component"]["bom-ref"]
        for d in bom["dependencies"]:
            self.assertIn(d["ref"], {**comps, root: None})
            for r in d["dependsOn"]:
                self.assertIn(r, comps)
        by_host = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
        self.assertTrue(all(wire[0]["bom-ref"] in by_host[d["bom-ref"]] for d in devices))
        vulns = {v["id"]: v for v in bom["vulnerabilities"]}
        self.assertEqual(set(vulns), {"CVE-2024-1111", "CVE-2024-2222"})                 # one entry per CVE, not per host
        v = vulns["CVE-2024-1111"]
        self.assertEqual(v["affects"], [{"ref": wire[0]["bom-ref"]}])
        self.assertEqual(v["ratings"][0]["score"], 9.8)
        self.assertEqual(v["ratings"][0]["severity"], "high")
        self.assertEqual(v["analysis"]["state"], "in_triage")
        self.assertEqual(v["published"], "2024-03-01T00:00:00Z")                         # date-only values become valid date-times
        self.assertEqual((sb._cdx_time("2024-03-01T10:00:00.000"), sb._cdx_time("2024-03-01T10:00:00+01:00")), ("2024-03-01T10:00:00.000Z", "2024-03-01T10:00:00+01:00"))
        self.assertIn({"name": "cisa:kev", "value": "true"}, v["properties"])
        self.assertNotIn("properties", vulns["CVE-2024-2222"])
        self.assertEqual({c["name"] for c in apps if "cpe" not in c}, {"Mystery Suite", "=EVIL() Tool"})  # unmapped software is still listed
        self.assertEqual({d["ref"]: d["dependsOn"] for d in bom["dependencies"]}[root], sorted(d["bom-ref"] for d in devices))
        self.assertEqual(bom["metadata"]["lifecycles"], [{"phase": "operations"}])
        self.assertEqual(bom["compositions"], [{"aggregate": "incomplete", "assemblies": [root]}])
        self.assertNotIn("authors", bom["metadata"])                                     # nothing invented when not supplied

    def test_cyclonedx_is_compact_and_descriptions_are_optional(self):
        self.world()
        self.scan("--cyclonedx")
        path = next(self.out.glob("sbom_cyclonedx_*.json"))
        self.assertNotIn("\n", path.read_text())
        bom = json.loads(path.read_text())
        self.assertTrue(any(v.get("description") for v in bom["vulnerabilities"]))
        path.unlink()
        self.scan("--cyclonedx", "--cyclonedx-no-descriptions")
        bom2 = json.loads(next(self.out.glob("sbom_cyclonedx_*.json")).read_text())
        self.assertTrue(all("description" not in v for v in bom2["vulnerabilities"]))
        self.assertEqual(len(bom2["vulnerabilities"]), len(bom["vulnerabilities"]))

    def test_author_and_product_identity_come_from_the_user(self):
        self.world()
        code, out, err = self.scan("--cyclonedx", "--sbom-author", "Dom Storey <dom@example.com>", "--product-name", "Plant 7", "--product-version", "2.1")
        self.assertEqual(code, 0, err)
        bom = json.loads(next(self.out.glob("sbom_cyclonedx_*.json")).read_text())
        self.assertEqual(bom["metadata"]["authors"], [{"name": "Dom Storey", "email": "dom@example.com"}])
        self.assertEqual((bom["metadata"]["component"]["name"], bom["metadata"]["component"]["version"]), ("Plant 7", "2.1"))
        self.assertEqual(sb.parse_author("https://example.com/me"), {"name": "https://example.com/me"})
        self.assertEqual(sb.parse_author("a@b.co".join(["<", ">"])), {"email": "a@b.co"})
        self.assertIsNone(sb.parse_author("  "))

    def test_nothing_identifying_is_sent_to_the_nvd(self):
        w = self.world()
        self.scan()
        sent = " ".join(str(r.url) for r in w.nvd_requests) + " ".join(r.content.decode() for r in w.nvd_requests)
        for secret in ("WIN-1", "WIN-2", "10.0.0.1", "host-1", "key-one"):
            self.assertNotIn(secret, sent)

    def test_second_run_uses_the_cache(self):
        w = self.world()
        self.scan()
        self.scan()
        self.assertEqual(len(w.nvd_requests), 1)

    def test_dry_run_makes_no_nvd_calls_and_writes_nothing(self):
        w = self.world()
        code, out, err = self.scan("--dry-run")
        self.assertEqual(code, 0)
        self.assertEqual(w.nvd_requests, [])
        self.assertFalse(self.out.exists())
        self.assertIn(WIRESHARK_CPE, out)
        self.assertIn("Mystery Suite", out)

    def test_min_cvss_and_kev_filters(self):
        self.world()
        self.scan("--min-cvss", "7")
        self.assertEqual({r["cve_id"] for r in self.read_csv("sbom_cves")}, {"CVE-2024-1111"})
        for f in self.out.glob("*"):
            f.unlink()
        self.scan("--kev-only")
        self.assertEqual({r["cve_id"] for r in self.read_csv("sbom_cves")}, {"CVE-2024-1111"})

    def test_windows_clause_is_sent_by_default_and_not_with_all_os(self):
        w = self.world()
        self.scan("--dry-run")
        self.assertIn("Like", json.dumps(w.graphql_vars[0]["filter"]))
        w.graphql_vars.clear()
        self.scan("--dry-run", "--all-os")
        self.assertNotIn("filter", w.graphql_vars[0])

    def test_rejected_os_filter_falls_back_to_unfiltered_scan(self):
        w = self.world(reject_os_filter=True)
        code, out, err = self.scan("--dry-run")
        self.assertEqual(code, 0, err)
        self.assertIn("OS filter was rejected", err)
        self.assertIn(WIRESHARK_CPE, out)

    # ---- target detection, site, url and config file -----------------------

    def test_standalone_icp_is_detected_and_queried_at_the_root(self):
        w = self.world(standalone_icp=True)
        code, out, err = self.scan("--dry-run")           # no flag needed
        self.assertEqual(code, 0, err)
        self.assertEqual(set(w.graphql_paths), {"/graphql"})
        self.assertIn("standalone ICP", err)
        self.assertIn(WIRESHARK_CPE, out)

    def test_icp_is_detected_by_probe_when_the_server_has_no_isem_field(self):
        w = self.world(standalone_icp=True)
        w.is_em_field = False
        code, out, err = self.scan("--dry-run")
        self.assertEqual(code, 0, err)
        self.assertIn("standalone ICP (detected by probe)", err)
        self.assertEqual(set(w.graphql_paths), {"/graphql"})

    def test_enterprise_manager_is_detected_and_its_site_name_is_used(self):
        w = self.world()
        code, out, err = self.scan("--dry-run")
        self.assertEqual(code, 0, err)
        self.assertIn("Enterprise Manager", err)
        self.assertIn(f"Site: London ({SITE})", err)
        self.assertIn(f"/{SITE}/graphql", set(w.graphql_paths))

    def test_authentication_failure_is_not_mistaken_for_an_icp(self):
        w = self.world()
        w.auth_fail = True
        code, out, err = self.scan("--dry-run")
        self.assertEqual(code, 1)
        self.assertIn("rejected the API key", err)

    def test_forced_mode_skips_detection(self):
        w = self.world(standalone_icp=True)
        code, out, err = self.scan("--dry-run", "--mode", "icp")
        self.assertEqual(code, 0, err)
        self.assertNotIn("isEm", " ".join(str(v) for v in w.graphql_vars))
        self.assertNotIn("(isEm)", err)

    def test_site_is_chosen_by_name_and_the_id_is_looked_up(self):
        w = self.world()
        w.sites = [("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Sydney"), (SITE, "London")]
        self.assertEqual(self.scan("--dry-run")[0], 1)    # several sites and none chosen
        code, out, err = self.scan("--dry-run", "--site", "london")   # case-insensitive
        self.assertEqual(code, 0, err)
        self.assertIn(f"/{SITE}/graphql", set(w.graphql_paths))

    def test_multiple_sites_without_a_choice_says_what_to_pass(self):
        w = self.world()
        w.sites = [("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Sydney"), (SITE, "London")]
        code, out, err = self.scan("--dry-run")
        self.assertEqual(code, 1)
        self.assertIn("--site NAME", err)
        self.assertIn("London", err)
        self.assertIn("Sydney", err)

    def test_unknown_site_name_lists_the_available_ones(self):
        self.world()
        code, out, err = self.scan("--dry-run", "--site", "Atlantis")
        self.assertEqual(code, 1)
        self.assertIn("No site named 'Atlantis'", err)
        self.assertIn("London", err)

    def test_site_all_scans_every_paired_site_and_labels_each(self):
        w = self.world()
        other = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        w.sites = [(other, "Sydney"), (SITE, "London")]
        w.site_hosts = {SITE: [_host(1, [("Wireshark 4.0.5 64-bit", "4.0.5")])], other: [_host(2, [("Wireshark 4.0.5 64-bit", "4.0.5")])]}
        code, out, err = self.scan("--site", "all")
        self.assertEqual(code, 0, err)
        by_site = {r["asset_name"]: r["site"] for r in self.read_csv("sbom_cves")}
        self.assertEqual(by_site, {"WIN-1": "London", "WIN-2": "Sydney"})

    def test_url_option_overrides_the_environment(self):
        w = self.world(standalone_icp=True)
        code, out, err = self.scan("--dry-run", "--url", "https://other.example/")
        self.assertEqual(code, 0, err)
        self.assertEqual({h for h, _, _ in w.graphql_calls}, {"other.example"})

    def write_config(self, text, mode=0o600):
        path = Path(self.tmp.name) / "targets.ini"
        path.write_text(text)
        path.chmod(mode)
        return str(path)

    def test_config_file_scans_several_icps_with_their_own_keys(self):
        w = self.world(standalone_icp=True)
        w.hosts_by_host = {
            "london.example": [_host(1, [("Wireshark 4.0.5 64-bit", "4.0.5")])],
            "sydney.example": [_host(2, [("Wireshark 4.0.5 64-bit", "4.0.5")])],
        }
        cfg = self.write_config(
            "[DEFAULT]\ntls_verify = 0\n"
            "[london]\nurl = https://london.example\napi_key = key-london\n"
            "[sydney]\nurl = https://sydney.example/\napi_key = key-sydney\n"
        )
        code, out, err = self.scan("--config", cfg)
        self.assertEqual(code, 0, err)
        keys = {(h, k) for h, _, k in w.graphql_calls}
        self.assertEqual(keys, {("london.example", "key=key-london"), ("sydney.example", "key=key-sydney")})
        by_site = {r["asset_name"]: r["site"] for r in self.read_csv("sbom_cves")}
        self.assertEqual(by_site, {"WIN-1": "london", "WIN-2": "sydney"})  # the section name labels ICP data

    def test_target_selects_a_section_and_unknown_targets_are_reported(self):
        w = self.world(standalone_icp=True)
        cfg = self.write_config("[london]\nurl = https://london.example\napi_key = k1\n[sydney]\nurl = https://sydney.example\napi_key = k2\n")
        self.scan("--dry-run", "--config", cfg, "--target", "Sydney")
        self.assertEqual({h for h, _, _ in w.graphql_calls}, {"sydney.example"})
        code, out, err = self.scan("--dry-run", "--config", cfg, "--target", "paris")
        self.assertEqual(code, 1)
        self.assertIn("paris", err)
        self.assertIn("Available: london, sydney", err)

    def test_config_api_key_can_come_from_an_environment_variable(self):
        w = self.world(standalone_icp=True)
        cfg = self.write_config("[london]\nurl = https://london.example\napi_key_env = LONDON_KEY\n")
        with mock.patch.dict(os.environ, {"LONDON_KEY": "from-env"}):
            code, out, err = self.scan("--dry-run", "--config", cfg)
        self.assertEqual(code, 0, err)
        self.assertEqual({k for _, _, k in w.graphql_calls}, {"key=from-env"})
        code, out, err = self.scan("--dry-run", "--config", cfg)   # variable now unset
        self.assertEqual(code, 1)
        self.assertIn("LONDON_KEY", err)

    def test_config_file_errors_are_clear(self):
        self.world()
        for text, needle in (("[a]\napi_key = k\n", "'url' is required"),
                             ("[a]\nurl = https://x\n", "api_key"),
                             ("[a]\nurl = https://x\napi_key = k\nmode = sideways\n", "mode must be"),
                             ("", "no [target] sections")):
            code, out, err = self.scan("--dry-run", "--config", self.write_config(text))
            self.assertEqual(code, 1, text)
            self.assertIn(needle, err)
        code, out, err = self.scan("--dry-run", "--config", "/no/such.ini")
        self.assertIn("not found", err)
        cfg = self.write_config("[a]\nurl = https://x\napi_key = k\n")
        self.assertIn("--url cannot be combined", self.scan("--dry-run", "--config", cfg, "--url", "https://y")[2])
        self.assertIn("--target needs --config", self.scan("--dry-run", "--target", "a")[2])

    def test_config_file_readable_by_others_triggers_a_warning(self):
        w = self.world(standalone_icp=True)
        cfg = self.write_config("[a]\nurl = https://x.example\napi_key = k\n", mode=0o644)
        code, out, err = self.scan("--dry-run", "--config", cfg)
        self.assertEqual(code, 0, err)
        self.assertIn("chmod 600", err)

    def test_there_is_no_api_key_option_on_the_command_line(self):
        self.world()
        with self.assertRaises(SystemExit):
            with redirect_stderr(io.StringIO()):
                cli.build_parser().parse_args(["sbom", "--api-key", "x"])

    # ---- software inventory, keys and Power BI ----------------------------

    def read_json(self, prefix):
        return json.loads(next(self.out.glob(f"{prefix}_*.json")).read_text())

    def test_software_inventory_lists_every_host_product_with_its_status(self):
        w = self.world()
        self.scan()
        sw = self.read_csv("sbom_software")
        got = {(r["asset_name"], r["product"], r["status"]) for r in sw}
        self.assertEqual(got, {
            ("WIN-1", "Wireshark 4.0.5 64-bit", "mapped"), ("WIN-2", "Wireshark 4.0.5 64-bit", "mapped"),
            ("WIN-1", "'=EVIL() Tool", "unmapped"), ("WIN-2", "Mystery Suite", "unmapped"),
        })
        ws = next(r for r in sw if r["asset_name"] == "WIN-1" and r["status"] == "mapped")
        self.assertEqual((ws["cve_count"], ws["max_cvss"], ws["kev_count"]), ("2", "9.8", "1"))
        self.assertEqual(ws["cpe"], WIRESHARK_CPE)
        self.assertEqual(ws["match_basis"], "curated")
        un = next(r for r in sw if r["status"] == "unmapped")
        self.assertEqual((un["cpe"], un["match_basis"], un["cve_count"]), ("", "", "0"))

    def test_keys_join_assets_to_software_to_findings(self):
        self.world()
        self.scan()
        software = self.read_json("sbom_software")
        findings = self.read_json("sbom_cves")
        ids = [r["software_id"] for r in software]
        self.assertEqual(len(ids), len(set(ids)))                       # unique: one row per host and product version
        self.assertTrue(all(len(i) == 16 for i in ids))
        by_id = {r["software_id"]: r for r in software}
        for f in findings:                                              # every finding hangs off exactly one software row
            parent = by_id[f["software_id"]]
            self.assertEqual((parent["asset_id"], parent["product"], parent["version"]), (f["asset_id"], f["product"], f["version"]))
        for r in software:                                              # cve_count matches the findings under it
            self.assertEqual(r["cve_count"], sum(1 for f in findings if f["software_id"] == r["software_id"]))

    def test_software_id_is_stable_and_distinguishes_host_product_and_version(self):
        a = sb.software_id("London", "host-1", "7-Zip", "9.20")
        self.assertEqual(a, sb.software_id("London", "host-1", "7-Zip", "9.20"))
        for other in (("Sydney", "host-1", "7-Zip", "9.20"), ("London", "host-2", "7-Zip", "9.20"),
                      ("London", "host-1", "7-Zip x64", "9.20"), ("London", "host-1", "7-Zip", "9.21")):
            self.assertNotEqual(a, sb.software_id(*other))

    def pbi_env(self, dataset=True):
        token = Path(self.tmp.name) / "token.json"
        token.write_text(json.dumps({"refresh_token": "r1"}))
        env = {"AZURE_TENANT_ID": "tenant", "AZURE_CLIENT_ID": "client", "POWERBI_WORKSPACE_ID": "ws1",
               "TOKEN_CACHE_FILE": str(token), "POWERBI_DATASET_ID": "ds-1" if dataset else "",
               "POWERBI_DATASET_NAME": "", "POWERBI_TABLE_NAME": ""}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)

    def test_powerbi_replaces_software_then_findings_and_leaves_assets_alone(self):
        w = self.world()
        self.pbi_env()
        code, out, err = self.scan("--powerbi")
        self.assertEqual(code, 0, err)
        base = "/v1.0/myorg/groups/ws1/datasets/ds-1/tables"
        calls = [(m, path) for m, path, q, h, b in w.pbi_requests]
        self.assertEqual(calls, [
            ("DELETE", f"{base}/sbom_software/rows"), ("POST", f"{base}/sbom_software/rows"),    # parent first
            ("DELETE", f"{base}/sbom_findings/rows"), ("POST", f"{base}/sbom_findings/rows"),
        ])                                                                                       # never touches `assets`
        self.assertEqual(w.pbi_requests[1][3]["authorization"], "Bearer tok")
        sw_rows = w.pbi_requests[1][4]["rows"]
        fd_rows = w.pbi_requests[3][4]["rows"]
        self.assertEqual((len(sw_rows), len(fd_rows)), (4, 4))
        self.assertEqual(set(sw_rows[0]), {c for c, _ in sb.SBOM_SOFTWARE_COLUMNS} - ({"max_cvss"} if "max_cvss" not in sw_rows[0] else set()))
        self.assertEqual(set(fd_rows[0]), {c for c, _ in sb.SBOM_FINDINGS_COLUMNS})
        self.assertTrue(all(isinstance(r["kev"], bool) for r in fd_rows))
        self.assertTrue({r["software_id"] for r in fd_rows} <= {r["software_id"] for r in sw_rows})
        self.assertIn("4 software row(s) and 4 finding(s)", out)

    def test_powerbi_rows_omit_unscored_numbers_and_skip_csv_escaping(self):
        rows = [{"software_id": "s", "asset_id": "a", "site": "x", "asset_name": "n", "ips": "", "product": "=X", "version": "1",
                 "cpe": "c", "match_basis": "curated", "cve_id": "CVE-1", "cvss_score": None, "severity": "",
                 "kev": 0, "published": "2024-01-01", "description": "d"}]
        out = sb.powerbi_rows(rows, "2026-01-01T00:00:00Z")[0]
        self.assertNotIn("cvss_score", out)
        self.assertIs(out["kev"], False)
        self.assertEqual(out["product"], "=X")  # not "'=X": it is not going into a spreadsheet cell
        sw = sb.powerbi_software_rows([{"software_id": "s", "asset_id": "a", "cve_count": 0, "max_cvss": None, "kev_count": 0}], "t")[0]
        self.assertNotIn("max_cvss", sw)
        self.assertEqual((sw["cve_count"], sw["kev_count"]), (0, 0))   # zero is a value, not missing

    def test_powerbi_without_dataset_id_fails_before_any_lookup(self):
        w = self.world()
        self.pbi_env(dataset=False)
        code, out, err = self.scan("--powerbi")
        self.assertEqual(code, 1)
        self.assertIn("create-dataset", err)
        self.assertEqual(w.nvd_requests, [])
        self.assertEqual(w.pbi_requests, [])

    def test_dry_run_with_powerbi_pushes_nothing(self):
        w = self.world()
        self.pbi_env()
        code, out, err = self.scan("--dry-run", "--powerbi")
        self.assertEqual(code, 0, err)
        self.assertEqual(w.pbi_requests, [])
        self.assertIn("nothing is pushed", err)

    def test_powerbi_failure_keeps_the_report_files_and_says_so(self):
        w = self.world()
        self.pbi_env()
        w.pbi_status = 403
        code, out, err = self.scan("--powerbi")
        self.assertEqual(code, 1)
        self.assertIn("report files above were written", err)
        self.assertTrue(list(self.out.glob("sbom_cves_*.csv")))
        self.assertTrue(list(self.out.glob("sbom_software_*.csv")))

    def create_dataset(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            empty_env = Path(self.tmp.name) / "empty.env"
            empty_env.write_text("")
            code = cli.main(["--env-file", str(empty_env), "create-dataset", *extra])
        return code, out.getvalue(), err.getvalue()

    def test_create_dataset_builds_three_related_tables(self):
        w = self.world()
        self.pbi_env(dataset=False)
        code, out, err = self.create_dataset()
        self.assertEqual(code, 0, err)
        self.assertIn("POWERBI_DATASET_ID=ds-123", out)
        method, path, q, headers, body = w.pbi_requests[0]
        self.assertEqual((method, path), ("POST", "/v1.0/myorg/groups/ws1/datasets"))
        self.assertIn("basicFIFO", q)
        self.assertEqual(body["name"], "Tenable OT Assets and SBOM")
        tables = {t["name"]: [c["name"] for c in t["columns"]] for t in body["tables"]}
        self.assertEqual(set(tables), {"assets", "sbom_software", "sbom_findings"})
        self.assertEqual(tables["assets"], [c.name for c in hx.resolve_columns("all")])      # exactly what `t1ote_export_assets.py assets` writes
        self.assertEqual(tables["sbom_software"], [c for c, _ in sb.SBOM_SOFTWARE_COLUMNS])
        rel = {r["name"]: (r["fromTable"], r["fromColumn"], r["toTable"], r["toColumn"]) for r in body["relationships"]}
        self.assertEqual(rel, {
            "assets_to_software": ("sbom_software", "asset_id", "assets", "asset_id"),            # many -> one
            "software_to_findings": ("sbom_findings", "software_id", "sbom_software", "software_id"),
        })
        for r in body["relationships"]:
            self.assertEqual(r["crossFilteringBehavior"], "OneDirection")
            self.assertIn(r["fromColumn"], tables[r["fromTable"]])                                # relationships name real columns
            self.assertIn(r["toColumn"], tables[r["toTable"]])

    def test_create_dataset_without_relationships_explains_the_manual_step(self):
        w = self.world()
        self.pbi_env(dataset=False)
        code, out, err = self.create_dataset("--no-relationships")
        self.assertEqual(code, 0, err)
        self.assertNotIn("relationships", w.pbi_requests[0][4])
        self.assertIn("No relationships were defined", out)
        self.assertIn("sbom_software[software_id] -> sbom_findings[software_id]", out)

    def test_dataset_name_and_assets_table_follow_the_environment(self):
        w = self.world()
        self.pbi_env(dataset=False)
        with mock.patch.dict(os.environ, {"POWERBI_DATASET_NAME": "Lab", "POWERBI_TABLE_NAME": "devices"}):
            self.create_dataset()
        body = w.pbi_requests[0][4]
        self.assertEqual(body["name"], "Lab")
        self.assertIn("devices", [t["name"] for t in body["tables"]])
        self.assertEqual(body["relationships"][0]["toTable"], "devices")

    # ---- mapping fixes -----------------------------------------------------

    def test_documentation_and_media_components_are_noise(self):
        for n in ("Studio 5000 Logix Designer Online Books v29.0.0", "Studio 5000 Logix Designer Start Page Media v29.00.00"):
            self.assertTrue(sb.is_noise(n), n)
        self.assertFalse(sb.is_noise("Studio 5000 Logix Designer v29.00.00 (CPR 9 SR 8)"))

    def test_linx_sibling_tools_are_not_mapped_to_linx(self):
        linx = sb.map_product("FactoryTalk Linx 6.40.00 (CPR 9 SR 14)", "6.40.00", [])[0]
        self.assertEqual(linx, "cpe:2.3:a:rockwellautomation:factorytalk_linx:6.40.00:*:*:*:*:*:*:*")
        self.assertEqual(sb.map_product("FactoryTalk Linx Redundancy Module Configuration Tool 9.01.01", "9.01.01", []), (None, ""))

    def test_version_variants(self):
        self.assertEqual(
            sb.cpe_version_variants("cpe:2.3:a:7-zip:7-zip:9.20.00.0:*:*:*:*:*:*:*"),
            ["cpe:2.3:a:7-zip:7-zip:9.20.00.0:*:*:*:*:*:*:*", "cpe:2.3:a:7-zip:7-zip:9.20.00:*:*:*:*:*:*:*",
             "cpe:2.3:a:7-zip:7-zip:9.20:*:*:*:*:*:*:*", "cpe:2.3:a:7-zip:7-zip:9.20.0:*:*:*:*:*:*:*"],
        )
        self.assertEqual(len(sb.cpe_version_variants("cpe:2.3:a:v:p:1.2.3:*:*:*:*:*:*:*")), 1)  # nothing to trim
        self.assertEqual(len(sb.cpe_version_variants("cpe:2.3:a:v:p:4.0:*:*:*:*:*:*:*")), 1)    # never below two parts

    def test_four_part_version_falls_back_to_the_form_nvd_knows(self):
        w = self.world()
        full = "cpe:2.3:a:7-zip:7-zip:9.20.00.0:*:*:*:*:*:*:*"
        short = "cpe:2.3:a:7-zip:7-zip:9.20:*:*:*:*:*:*:*"
        w.hosts = [_host(1, [("7-Zip 9.20 (x64 edition)", "9.20.00.0")])]
        w.nvd[full] = None
        w.nvd["cpe:2.3:a:7-zip:7-zip:9.20.00:*:*:*:*:*:*:*"] = None  # NVD answers 404 for spellings it lacks
        w.nvd[short] = [_cve("CVE-2020-0001", 7.5)]
        code, out, err = self.scan()
        self.assertEqual(code, 0, err)
        row = self.read_csv("sbom_cves")[0]
        self.assertEqual(row["cve_id"], "CVE-2020-0001")
        self.assertEqual(row["cpe"], short)
        self.assertEqual(row["match_basis"], "curated+version_trimmed")

    def test_exact_version_is_preferred_when_nvd_knows_it(self):
        w = self.world()
        w.hosts = [_host(1, [("7-Zip 9.20 (x64 edition)", "9.20.00.0")])]
        w.nvd["cpe:2.3:a:7-zip:7-zip:9.20.00.0:*:*:*:*:*:*:*"] = [_cve("CVE-2020-0002", 5.0)]
        self.scan()
        row = self.read_csv("sbom_cves")[0]
        self.assertEqual(row["match_basis"], "curated")
        self.assertEqual(len(w.nvd_requests), 1)

    def test_paging_uses_small_pages_and_follows_cursor(self):
        w = self.world()
        self.scan("--dry-run", "--page-size", "2")
        self.assertEqual([v["pageSize"] for v in w.graphql_vars], [2, 2])
        self.assertEqual(w.graphql_vars[1]["after"], "2")

    def test_limit_never_overfetches(self):
        w = self.world()
        self.scan("--dry-run", "--limit", "1")
        self.assertEqual([v["pageSize"] for v in w.graphql_vars], [1])

    def test_user_map_adds_mappings(self):
        w = self.world()
        w.nvd["cpe:2.3:a:acme:mystery:2.0:*:*:*:*:*:*:*"] = [_cve("CVE-9", 6.0)]
        mapfile = Path(self.tmp.name) / "m.json"
        mapfile.write_text(json.dumps({"^mystery suite": ["acme", "mystery"]}))
        code, out, err = self.scan("--map-file", str(mapfile))
        self.assertEqual(code, 0, err)
        rows = [r for r in self.read_csv("sbom_cves") if r["cve_id"] == "CVE-9"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["match_basis"], "user_map")

    def test_unknown_cpe_is_reported_not_swallowed(self):
        w = self.world()
        w.nvd[WIRESHARK_CPE] = None
        self.scan()
        un = self.read_csv("sbom_unmapped")
        self.assertIn(("Wireshark 4.0.5 64-bit", "CPE not in NVD dictionary"), {(r["product"], r["reason"]) for r in un})
        self.assertEqual(self.read_csv("sbom_cves"), [])

    def test_bad_arguments_fail_before_any_network_call(self):
        w = self.world()
        for args in (["--limit", "0"], ["--page-size", "0"], ["--page-size", "101"], ["--subnet", "nope"],
                     ["--map-file", "/no/such.json"], ["--subnet", "10.0.0.0/24", "--ip-range", "10.0.0.1-10.0.0.9"]):
            code, out, err = self.scan(*args)
            self.assertEqual(code, 1, args)
            self.assertIn("Error:", err)
        self.assertEqual(w.graphql_vars, [])

    def test_missing_env_file_exit_code(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(cli.main(["--env-file", "/no/such/.env", "sbom"]), 2)



class CpeProductTests(unittest.TestCase):
    def test_family_key_is_unescaped_and_versionless(self):
        self.assertEqual(sb.cpe_product(r"cpe:2.3:a:microsoft:visual_c\+\+:14.0:*:*:*:*:*:*:*"), "microsoft:visual_c++")
        self.assertEqual(sb.cpe_product(WIRESHARK_CPE), "wireshark:wireshark")
        self.assertEqual(sb.cpe_product(""), "")

    def test_fragment_flag_only_on_build_pieces(self):
        self.assertTrue(sb._FRAGMENT_RE.search("Microsoft Visual C++ 2015 x64 Additional Runtime"))
        self.assertFalse(sb._FRAGMENT_RE.search("Wireshark"))

if __name__ == "__main__":
    unittest.main()
