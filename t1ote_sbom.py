# SPDX-License-Identifier: Apache-2.0
"""@file t1ote_sbom.py
@brief Software inventory (SBOM) to CVE report for Tenable OT Windows assets.

Reads the software list that Tenable OT collected from each Windows host
(WMI / OT Agent data in the asset's `details`), maps the products to CPE
names, asks the NVD for the CVEs that apply to each product *version*, and
writes one CSV/JSON row per host, software item and CVE.

    Tenable OT (EM or ICP) --GraphQL--> installed software  (via t1ote_core.Tenable)
        -> normalise + drop noise (EDS/module-profile data files, SDK packs...)
        -> map product name to a CPE   (curated table, your --map-file, optional fuzzy)
        -> NVD API 2.0: CVEs for that CPE (cached on disk, rate-limited)
        -> CSV + JSON report, plus a list of software that could not be mapped

IMPORTANT: results are *inferred*. Product names reported by Windows are
free text; the mapping to NVD's CPE dictionary is best-effort, so expect both
false positives and misses. Treat the output as a triage list, not as audit
evidence. The report always includes how each match was made (`match_basis`).

Only product names and versions are sent to the NVD. No host names, IP
addresses or asset ids ever leave your network.

Output goes to CSV and JSON files (findings, software inventory, unmapped list)
and, optionally (`sbom --powerbi`), to the `sbom_software` and `sbom_findings`
tables of a Power BI push dataset that also holds the asset export's `assets`
table, related by `asset_id` and `software_id`.

This module is the SBOM engine; its command line is `t1ote_export_assets.py sbom` (and `run`).
Run `python t1ote_export_assets.py sbom --help` for the options.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlencode

import t1ote_core as hx
import t1ote_sql as sq
from t1ote_core import ExportError, log

__version__ = "0.1.0"

# ==========================================================================
# Constants
# ==========================================================================

## @brief NVD CVE API 2.0 endpoint.
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

## @brief NVD CPE dictionary API 2.0 endpoint (only used by `--fuzzy`).
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

## @brief Page size for the NVD (its documented maximum for CVEs is 2000).
NVD_PAGE = 2000

## @brief Seconds between NVD requests. NVD allows 5 requests / 30 s without
#  an API key and 50 / 30 s with one; these stay safely inside both.
NVD_INTERVAL_NO_KEY = 6.5
NVD_INTERVAL_WITH_KEY = 0.7

## @brief Print progress and save the cache after this many NVD requests, so an
#  interrupted run (Ctrl-C, dropped connection) keeps the lookups already done.
NVD_CHECKPOINT_EVERY = 25

## @brief How long a cached NVD answer is trusted.
CACHE_TTL_DAYS = 7

## @brief Assets requested per GraphQL page. Deliberately small: each Windows
#  host's `details` is ~80 KB of JSON, so a big page makes huge responses.
SBOM_PAGE_SIZE = 10

## @brief GraphQL: a page of assets with their collected host details.
_QUERY_SBOM_ASSETS = """
query Q($pageSize: Int!, $after: String, $filter: AssetExpressionsParams) {
  assets(first: $pageSize, after: $after, filter: $filter) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes { id name os ips(first: 10) { nodes } details }
  }
}
"""

## @brief One asset's full `details`. The list query above omits the large
#  `windows.installedSoftware` table on some systems, so hosts that report a
#  WMI `windows` block but no software are re-read with this.
_QUERY_ASSET_DETAILS = "query Q($id: ID!) { asset(id: $id) { details } }"

## @brief Server-side scope clause: Windows hosts only.
_WINDOWS_CLAUSE = {"field": "os", "op": "Like", "values": ["%Windows%"]}

## @brief Software that is not a CVE-bearing product: engineering data files
#  (EDS / module profiles), SDK/targeting packs, language packs and the like.
#  A Rockwell engineering host lists hundreds of these (423 entries, ~400 of
#  them noise on the lab host). Disable with `--keep-noise`.
_NOISE_RE = re.compile(
    r"module profile|\bprofiles?\b|ethernet/ip|ethernet_ip|\bdtm\b|dtm library"
    r"|language pack|language resources|prerequisites|targeting pack"
    r"|interop assemblies|xaml designer|help viewer|build tools|services hub"
    r"|visual studio \d{4} (shell|xaml)|visual studio ultimate"
    r"|^update for |update health tools|release notes|uninstaller|help enu"
    r"|\bsamples?\b|catalog services|firewall configuration utility"
    r"|\bsdk\b|\bdriver package\b"
    r"|online books|start page media",
    re.IGNORECASE,
)

## @brief Curated product-name -> (vendor, product) NVD CPE mappings.
#  @details Matched against the cleaned, lower-cased product name. These are
#  best-effort: if NVD has no such CPE the product is reported as unmapped
#  (not silently dropped). Extend per-customer with `--map-file`.
_CURATED_MAP: list[tuple[str, str, str]] = [
    (r"^google chrome", "google", "chrome"),
    (r"^microsoft edge$", "microsoft", "edge_chromium"),
    (r"^wireshark", "wireshark", "wireshark"),
    (r"^npcap", "nmap", "npcap"),
    (r"^tightvnc", "tightvnc", "tightvnc"),
    (r"^vmware tools", "vmware", "tools"),
    (r"^7-zip", "7-zip", "7-zip"),
    (r"^putty", "putty", "putty"),
    (r"^studio 5000 logix designer", "rockwellautomation", "studio_5000_logix_designer"),
    # Exactly "FactoryTalk Linx" (optionally with a "(CPR ..)" suffix): sibling tools such as the
    # Redundancy Module Configuration Tool are separate products with their own version numbers.
    (r"^factorytalk linx(?:\s*\(cpr[^)]*\))?$", "rockwellautomation", "factorytalk_linx"),
    (r"^factorytalk services platform", "rockwellautomation", "factorytalk_services_platform"),
    (r"^rslinx classic", "rockwellautomation", "rslinx_classic"),
    (r"^controlflash plus$", "rockwellautomation", "controlflash_plus"),
    (r"^controlflash$", "rockwellautomation", "controlflash"),
    (r"^connected components workbench", "rockwellautomation", "connected_components_workbench"),
    (r"^codemeter runtime kit", "wibu", "codemeter_runtime"),
]

## @brief CVSS metric families in preference order (newest first).
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

## @brief Product names that are usually one piece of a larger install (a build fragment).
#  Used only to annotate the `suggest-map` review sheet; nothing is dropped or mapped from it.
_FRAGMENT_RE = re.compile(
    r"visual c\+\+ .*(additional|minimum|debug|runtime|redistributable)|vc_runtime|vcredist"
    r"|(tia portal|step 7|wincc).*(support|tour|compcheck|package|update|hsp|resources)"
    r"|sql server .*(common|browser|setup|support|vss|writer|client|connectivity|native|shared|management)"
    r"|microsoft \.net (host|runtime|targeting)|\b(language|resources|enu)\b",
    re.I,
)

## @brief Report columns, in order.
REPORT_COLUMNS = [
    "site", "asset_id", "software_id", "asset_name", "ips", "product", "version", "cpe", "cpe_product",
    "match_basis", "cve_id", "cvss_score", "severity", "kev", "published",
    "description",
]

## @brief Columns of the software inventory (the SBOM proper): one row per product version on a host.
SOFTWARE_COLUMNS = [
    "software_id", "asset_id", "asset_name", "site", "product", "version", "cpe", "cpe_product", "match_basis",
    "status", "reason", "cve_count", "max_cvss", "kev_count",
]

## @brief Columns of the "unmapped software" report.
UNMAPPED_COLUMNS = ["product", "version", "reason", "hosts"]


# ==========================================================================
# Software extraction and normalisation (pure functions)
# ==========================================================================


## @brief Pull the installed-software list out of an asset's `details` blob.
#  @details Prefers the raw `windows.installedSoftware` list; falls back to
#  the UI-table form (`installedSoftware.data`) if that is all there is.
#  @param details The `details` JSON (dict, or a JSON string), or `None`.
#  @return A list of `(name, version)` tuples (empty when the host reported none).
def extract_software(details: Any) -> list[tuple[str, str]]:
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except ValueError:
            return []
    if not isinstance(details, dict):
        return []
    win = details.get("windows") or {}
    raw = win.get("installedSoftware")
    out: list[tuple[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("name"):
                out.append((str(item["name"]).strip(), str(item.get("version") or "").strip()))
        return out
    table = details.get("installedSoftware")
    if isinstance(table, dict):
        for item in table.get("data") or []:
            if isinstance(item, dict) and item.get("Name"):
                out.append((str(item["Name"]).strip(), str(item.get("Version") or "").strip()))
    return out


## @brief True for entries that are data files / SDK packs rather than products.
def is_noise(name: str) -> bool:
    return bool(_NOISE_RE.search(name))


## @brief Strip architecture words and a trailing copy of the version from a
#         product name, and collapse whitespace.
#  @example "Wireshark 4.0.5 64-bit" with version "4.0.5" -> "Wireshark"
def clean_name(name: str, version: str = "") -> str:
    n = re.sub(r"\((?:x64|x86|64-bit|32-bit|amd64)\)", " ", name, flags=re.IGNORECASE)
    n = re.sub(r"\b(?:64-bit|32-bit|x64|x86|amd64)\b", " ", n, flags=re.IGNORECASE)
    if version:
        n = re.sub(r"\s*" + re.escape(version) + r"\b", " ", n)
    return re.sub(r"\s+", " ", n).strip(" -_")


## @brief Reduce a version string to the leading dotted-number part.
#  @return e.g. "4.31.00 CPR 9 SR 13.0" -> "4.31.00"; `None` if there is none.
def clean_version(version: str) -> str | None:
    m = re.match(r"\s*(\d+(?:\.\d+)*)", version or "")
    return m.group(1) if m else None


## @brief Backslash-escape the characters that are special in a CPE 2.3 string.
def _cpe_escape(text: str) -> str:
    return re.sub(r"([\\:*?!\"#$%&'()+,/;<=>@\[\]^`{|}~])", r"\\\1", text)


## @brief Build a version-specific CPE 2.3 name for an application.
def make_cpe(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{_cpe_escape(vendor)}:{_cpe_escape(product)}:{_cpe_escape(version)}:*:*:*:*:*:*:*"


## @brief The product family of a CPE: `vendor:product`, unescaped, without the version.
#  @details Every fragment of one product (all the Visual C++ pieces, say) shares this
#  value, so it is the exact key for grouping or de-duplicating findings in BI or SQL.
#  @return `vendor:product`, or an empty string when there is no CPE.
def cpe_product(cpe: str) -> str:
    parts = re.split(r"(?<!\\):", cpe or "")
    if len(parts) < 5:
        return ""
    return re.sub(r"\\(.)", r"\1", parts[3]) + ":" + re.sub(r"\\(.)", r"\1", parts[4])


## @brief Version spellings to try for a CPE, most specific first.
#  @details Windows often reports four-part installer versions (`9.20.00.0`,
#  `0.76.0.0`) while NVD lists the product as `9.20` or `0.76`. When NVD does not
#  know the exact CPE, the same product is tried with trailing zero segments
#  removed (and with leading zeros normalised), so those products are not
#  silently reported as having no CVEs. Matches made this way are labelled
#  `+version_trimmed` in `match_basis`.
#  @param cpe A version-specific CPE 2.3 name from `make_cpe`.
#  @return A list of CPE names, the original first, without duplicates.
def cpe_version_variants(cpe: str) -> list[str]:
    parts = re.split(r"(?<!\\):", cpe)
    if len(parts) < 6 or not re.fullmatch(r"\d+(?:\.\d+)*", parts[5]):
        return [cpe]
    segs = parts[5].split(".")
    versions = [parts[5]]
    cur = segs
    while len(cur) > 2 and int(cur[-1]) == 0:
        cur = cur[:-1]
        versions.append(".".join(cur))
    for v in list(versions[1:]):
        versions.append(".".join(str(int(x)) for x in v.split(".")))
    seen: list[str] = []
    for v in versions:
        if v not in seen:
            seen.append(v)
    return [":".join(parts[:5] + [v] + parts[6:]) for v in seen]


## @brief Load a customer mapping file.
#  @details JSON object: `{"regex on lower-case cleaned name": ["vendor", "product"]}`.
#  @throws ExportError On unreadable/invalid files or bad regexes.
def load_map_file(path: str | None) -> list[tuple[str, str, str]]:
    if not path:
        return []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ExportError(f"--map-file {path!r} could not be read as JSON: {e}") from e
    if not isinstance(data, dict):
        raise ExportError("--map-file must be a JSON object of {regex: [vendor, product]}.")
    out: list[tuple[str, str, str]] = []
    for pattern, target in data.items():
        if not (isinstance(target, list) and len(target) == 2 and all(isinstance(t, str) and t for t in target)):
            raise ExportError(f"--map-file entry {pattern!r} must map to [vendor, product].")
        try:
            re.compile(pattern)
        except re.error as e:
            raise ExportError(f"--map-file has an invalid regex {pattern!r}: {e}") from e
        # A CPE name never contains a backslash; one here is a leftover CPE escape (`visual_c\\+\\+`).
        out.append((pattern, *(re.sub(r"\\(.)", r"\1", t) for t in target)))
    return out


## @brief A software product (name + version) and the mapping decision for it.
@dataclass
class Product:
    ## Name as reported by Windows.
    name: str
    ## Version as reported by Windows.
    version: str
    ## Version-specific CPE, or `None` if unmapped.
    cpe: str | None = None
    ## How the CPE was chosen: `curated`, `user_map` or `nvd_keyword`.
    basis: str = ""
    ## Why it is unmapped (empty when mapped).
    reason: str = ""
    ## Host ids that report this exact product + version.
    hosts: set = field(default_factory=set)


## @brief Map a product to a CPE using the curated table, then the user map.
#  @details The user map is checked first so a customer can override a curated
#  entry. Fuzzy (NVD keyword) matching is handled separately by `Resolver`.
#  @return `(cpe, basis)` or `(None, "")` when no table entry matches.
def map_product(name: str, version: str, user_map: list[tuple[str, str, str]]) -> tuple[str | None, str]:
    ver = clean_version(version)
    if not ver:
        return None, ""
    cleaned = clean_name(name, version).lower()
    for table, basis in ((user_map, "user_map"), (_CURATED_MAP, "curated")):
        for pattern, vendor, product in table:
            if re.search(pattern, cleaned):
                return make_cpe(vendor, product, ver), basis
    return None, ""


# ==========================================================================
# NVD client (rate-limited, cached)
# ==========================================================================


## @brief Small JSON-file cache with a time-to-live.
class DiskCache:
    ## @param path Cache file (created on first save), or `None` for memory-only.
    #  @param ttl_days Entries older than this are ignored.
    def __init__(self, path: Path | None, ttl_days: float = CACHE_TTL_DAYS) -> None:
        self.path = path
        self.ttl = ttl_days * 86400
        self._data: dict[str, Any] = {}
        self._dirty = False
        if path and path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self._data = loaded
            except (OSError, ValueError):
                self._data = {}  # a corrupt cache is just a cold cache

    def get(self, key: str) -> Any:
        entry = self._data.get(key)
        if isinstance(entry, dict) and time.time() - float(entry.get("ts", 0)) < self.ttl:
            return entry.get("data")
        return None

    def put(self, key: str, value: Any) -> None:
        self._data[key] = {"ts": time.time(), "data": value}
        self._dirty = True

    def save(self) -> None:
        if not (self.path and self._dirty):
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data), encoding="utf-8")
        tmp.replace(self.path)
        self._dirty = False


## @brief Reduce one NVD `cve` object to the fields the report needs.
#  @return A dict, or `None` for rejected CVEs.
def parse_cve(cve: dict[str, Any]) -> dict[str, Any] | None:
    if (cve.get("vulnStatus") or "").lower() == "rejected":
        return None
    score: float | None = None
    severity = ""
    metrics = cve.get("metrics") or {}
    for key in _CVSS_KEYS:
        entries = metrics.get(key) or []
        if entries:
            m = entries[0]
            data = m.get("cvssData") or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or m.get("baseSeverity") or ""
            break
    desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    return {
        "id": cve.get("id"),
        "published": (cve.get("published") or "")[:10],
        "score": score,
        "severity": severity,
        "kev": bool(cve.get("cisaExploitAdd")),
        "description": " ".join(desc.split())[:300],
    }


## @brief Client for the NVD API 2.0.
class NvdClient:
    ## @param api_key NVD API key (raises the rate limit ten-fold), or `""`.
    #  @param cache A `DiskCache`.
    #  @param interval Seconds between requests; defaults from `api_key`.
    def __init__(self, api_key: str, cache: DiskCache, interval: float | None = None) -> None:
        self.api_key = api_key
        self.cache = cache
        self.interval = interval if interval is not None else (NVD_INTERVAL_WITH_KEY if api_key else NVD_INTERVAL_NO_KEY)
        self._http = hx.make_client(verify=True, timeout=60.0)
        self._last = 0.0
        self.requests_made = 0

    ## @brief GET with throttling and retry. Returns `None` for HTTP 404.
    #  @throws ExportError If NVD keeps refusing or returns a non-JSON body.
    def _get(self, url: str) -> dict[str, Any] | None:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(5):
            wait = self.interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            try:
                resp = self._http.get(url, headers=headers)
            except Exception as e:  # transport errors: retry, then report
                if attempt == 4:
                    raise ExportError(f"Could not reach the NVD: {e}") from e
                time.sleep(2 ** attempt * 2)
                continue
            self.requests_made += 1
            if self.requests_made % NVD_CHECKPOINT_EVERY == 0:
                self.cache.save()
                log(f"  NVD: {self.requests_made} requests made so far (cache saved)")
            if resp.status_code == 404:
                return None  # NVD answers 404 for a CPE it does not know
            if resp.status_code in (403, 429, 502, 503, 504):
                # 403 is how NVD signals "slow down". Back off and retry.
                time.sleep(2 ** attempt * 5)
                continue
            if resp.status_code >= 400:
                raise ExportError(f"NVD returned HTTP {resp.status_code}: {resp.text[:200]}")
            try:
                return resp.json()
            except ValueError as e:
                raise ExportError("NVD returned a non-JSON response.") from e
        raise ExportError("NVD kept refusing requests (rate limit?). Set NVD_API_KEY, or retry later.")

    ## @brief CVEs that apply to a version-specific CPE.
    #  @return `(cves, known)`. `known` is False when NVD does not recognise the
    #          CPE (so the caller can report "unknown CPE", not "no CVEs").
    def cves_for_cpe(self, cpe: str) -> tuple[list[dict[str, Any]], bool]:
        key = "cve:" + cpe
        cached = self.cache.get(key)
        if cached is not None:
            return cached["cves"], cached["known"]
        cves: list[dict[str, Any]] = []
        start = 0
        known = True
        while True:
            q = urlencode({"cpeName": cpe, "resultsPerPage": NVD_PAGE, "startIndex": start})
            body = self._get(f"{NVD_CVE_URL}?{q}&isVulnerable")
            if body is None:
                known = False
                break
            for v in body.get("vulnerabilities") or []:
                parsed = parse_cve(v.get("cve") or {})
                if parsed:
                    cves.append(parsed)
            start += int(body.get("resultsPerPage") or 0)
            if start >= int(body.get("totalResults") or 0) or not body.get("resultsPerPage"):
                break
        self.cache.put(key, {"cves": cves, "known": known})
        return cves, known

    ## @brief Candidate `(vendor, product)` pairs for a product name (fuzzy).
    def keyword_candidates(self, name: str) -> list[tuple[str, str]]:
        key = "kw:" + name.lower()
        cached = self.cache.get(key)
        if cached is not None:
            return [tuple(c) for c in cached]  # type: ignore[misc]
        q = urlencode({"keywordSearch": name, "resultsPerPage": 20})
        body = self._get(f"{NVD_CPE_URL}?{q}") or {}
        pairs: list[tuple[str, str]] = []
        for p in body.get("products") or []:
            cpe = (p.get("cpe") or {})
            if cpe.get("deprecated"):
                continue
            parts = re.split(r"(?<!\\):", cpe.get("cpeName") or "")
            if len(parts) > 4 and parts[2] == "a":
                pair = (re.sub(r"\\(.)", r"\1", parts[3]), re.sub(r"\\(.)", r"\1", parts[4]))   # CPE escapes are not part of the name
                if pair not in pairs:
                    pairs.append(pair)
        self.cache.put(key, [list(p) for p in pairs])
        return pairs


## @brief Accept a fuzzy candidate only when its words clearly appear in the name.
#  @details The vendor or product token must appear in the cleaned product
#  name. This is deliberately strict: precision over recall.
def fuzzy_pick(name: str, candidates: list[tuple[str, str]]) -> tuple[str, str] | None:
    lowered = clean_name(name).lower()
    for vendor, product in candidates:
        ptoks = product.replace("_", " ").lower()
        if ptoks and ptoks in lowered and (vendor.replace("_", " ").lower() in lowered or len(ptoks) >= 6):
            return vendor, product
    return None


# ==========================================================================
# Collecting software from Tenable
# ==========================================================================


## @brief Combine the Windows clause with any other scope filter (AND).
def with_windows_clause(filt: dict | None) -> dict:
    if filt is None:
        return dict(_WINDOWS_CLAUSE)
    if filt.get("op") == "And":
        return {"op": "And", "expressions": list(filt["expressions"]) + [_WINDOWS_CLAUSE]}
    return {"op": "And", "expressions": [filt, _WINDOWS_CLAUSE]}


## @brief Page through assets with their `details`, yielding one asset at a time.
#  @param tenable A `t1ote_core.Tenable` client.
#  @param site_id Site machine id, or `None` to query the root endpoint (standalone ICP).
#  @param filt Scope filter (already includes the Windows clause if wanted).
#  @param page_size Assets per request.
#  @param limit Stop after this many assets, or `None`.
#  @throws ExportError Propagated from the client.
def iter_assets(
    tenable: hx.Tenable, site_id: str | None, filt: dict | None, page_size: int, limit: int | None
) -> Iterator[dict[str, Any]]:
    cursor: str | None = None
    seen = 0
    while limit is None or seen < limit:
        size = page_size if limit is None else min(page_size, limit - seen)
        variables: dict[str, Any] = {"pageSize": size}
        if cursor:
            variables["after"] = cursor
        if filt is not None:
            variables["filter"] = filt
        conn = tenable.query(_QUERY_SBOM_ASSETS, variables, site_id=site_id).get("assets") or {}
        page = conn.get("nodes") or []
        for node in page:
            seen += 1
            yield node
        info = conn.get("pageInfo") or {}
        cursor = info.get("endCursor")
        log(f"  scanned {seen} / {conn.get('totalCount') or '?'} assets")
        if not info.get("hasNextPage") or not page or not cursor:
            break
        if seen >= hx.SAFETY_MAX_ASSETS:
            log(f"  stopping at the {hx.SAFETY_MAX_ASSETS}-asset safety limit")
            break


## @brief What was found on the Tenable side.
@dataclass
class Inventory:
    ## Distinct products keyed by `(name, version)`.
    products: dict = field(default_factory=dict)
    ## Host info keyed by asset id: `{"name", "ips", "site"}`.
    hosts: dict = field(default_factory=dict)
    ## Counters for the summary.
    assets_scanned: int = 0
    ## Assets whose details carry a WMI `windows` block (software may still be absent).
    assets_with_wmi: int = 0
    assets_with_software: int = 0
    items_seen: int = 0
    noise_dropped: int = 0


## @brief Fill in the software list for WMI-reporting hosts whose list-query
#  `details` lacks it, by fetching that asset's full `details`.
#  @details Only hosts with a `windows` block and no software are re-read, so
#  non-Windows and passively-seen assets cost nothing extra. A failed fetch is
#  logged and the asset is kept as-is (it is then counted as having no software).
#  @param tenable Tenable client.
#  @param site_id Site machine id, or `None` (standalone ICP).
#  @param nodes Asset nodes from `iter_assets`.
#  @return A generator of nodes, with `details` replaced where it was refetched.
def with_full_details(tenable: hx.Tenable, site_id: str | None, nodes: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for node in nodes:
        d = node.get("details")
        if isinstance(d, str):
            try:
                d = json.loads(d)
            except ValueError:
                d = None
        if isinstance(d, dict) and d.get("windows") and not extract_software(d):
            try:
                full = tenable.query(_QUERY_ASSET_DETAILS, {"id": node["id"]}, site_id=site_id).get("asset") or {}
            except ExportError as e:
                log(f"  could not read details for {node.get('name')}: {e}")
            else:
                if full.get("details"):
                    node = {**node, "details": full["details"]}
        yield node


## @brief Walk the assets and build the inventory.
#  @param assets Iterable of asset nodes (see `iter_assets`).
#  @param keep_noise Keep EDS/module-profile style entries.
#  @param site_label Site (or ICP target) name recorded against each host.
#  @param inv Existing inventory to add to (for scans over several sites/targets).
#  @return The inventory.
def collect_inventory(
    assets: Iterator[dict[str, Any]], keep_noise: bool, site_label: str, inv: Inventory | None = None
) -> Inventory:
    inv = inv if inv is not None else Inventory()
    for node in assets:
        inv.assets_scanned += 1
        details = node.get("details")
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except ValueError:
                details = None
        if isinstance(details, dict) and details.get("windows"):
            inv.assets_with_wmi += 1
        software = extract_software(details)
        if not software:
            continue
        inv.assets_with_software += 1
        inv.hosts[node["id"]] = {
            "name": node.get("name") or "",
            "ips": ", ".join((node.get("ips") or {}).get("nodes") or []),
            "site": site_label,
        }
        for name, version in software:
            inv.items_seen += 1
            if not keep_noise and is_noise(name):
                inv.noise_dropped += 1
                continue
            p = inv.products.setdefault((name, version), Product(name, version))
            p.hosts.add(node["id"])
    return inv


# ==========================================================================
# Resolving products to CVEs
# ==========================================================================


## @brief Map every product to a CPE (curated, user map, optional fuzzy).
#  @param inv The inventory; products are updated in place.
#  @param user_map Customer mappings from `--map-file`.
#  @param nvd NVD client, needed only for `fuzzy`.
#  @param fuzzy Try NVD keyword search for products the tables do not know.
def resolve_products(inv: Inventory, user_map: list[tuple[str, str, str]], nvd: NvdClient | None, fuzzy: bool) -> None:
    for p in inv.products.values():
        cpe, basis = map_product(p.name, p.version, user_map)
        if cpe:
            p.cpe, p.basis = cpe, basis
            continue
        ver = clean_version(p.version)
        if not ver:
            p.reason = "no usable version"
            continue
        if fuzzy and nvd is not None:
            pick = fuzzy_pick(p.name, nvd.keyword_candidates(clean_name(p.name, p.version)))
            if pick:
                p.cpe, p.basis = make_cpe(pick[0], pick[1], ver), "nvd_keyword"
                continue
        p.reason = "no CPE mapping"


## @brief Stable identifier of one product version on one host.
#  @details The key that joins the three Power BI tables: `assets[asset_id]` ->
#  `sbom_software[asset_id]`, and `sbom_software[software_id]` ->
#  `sbom_findings[software_id]`. Product name and version are the *reported* values,
#  so the id stays the same however the mapping tables change.
#  @return A 16-character hex string.
def software_id(site: str, asset_id: str, product: str, version: str) -> str:
    raw = "\x1f".join((site, asset_id, product, version))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


## @brief Build the software inventory and the CVE findings.
#  @param inv Resolved inventory.
#  @param nvd NVD client.
#  @param min_cvss Drop CVEs scored below this (unscored CVEs are kept).
#  @param kev_only Keep only CVEs in CISA's Known Exploited list.
#  @return `(findings, unmapped, software)`: one finding per host, product and CVE;
#          one unmapped entry per product version; one software row per host and
#          product version (with its mapping `status` and CVE counts).
def build_report(
    inv: Inventory, nvd: NvdClient, min_cvss: float, kev_only: bool
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    unmapped: list[dict[str, Any]] = []
    software: list[dict[str, Any]] = []
    total = sum(1 for p in inv.products.values() if p.cpe)
    done = 0
    for p in sorted(inv.products.values(), key=lambda x: (x.name.lower(), x.version)):
        status, reason, used_cpe, basis = "mapped", "", p.cpe or "", p.basis
        kept: list[dict[str, Any]] = []
        if not p.cpe:
            status, reason, basis = "unmapped", p.reason, ""
            unmapped.append({"product": p.name, "version": p.version, "reason": reason, "hosts": len(p.hosts)})
        else:
            done += 1
            log(f"  [{done}/{total}] {p.name} {p.version}")
            cves: list[dict[str, Any]] = []
            known = False
            for candidate in cpe_version_variants(p.cpe):
                cves, known = nvd.cves_for_cpe(candidate)
                if known:
                    used_cpe = candidate
                    break
            if not known:
                status, reason = "cpe_not_in_nvd", "CPE not in NVD dictionary"
                unmapped.append({"product": p.name, "version": p.version, "reason": reason, "hosts": len(p.hosts)})
            else:
                if used_cpe != p.cpe:
                    basis = f"{p.basis}+version_trimmed"
                kept = [
                    c for c in cves
                    if not (kev_only and not c["kev"]) and not (c["score"] is not None and c["score"] < min_cvss)
                ]
        scores = [c["score"] for c in kept if c["score"] is not None]
        for host_id in sorted(p.hosts):
            h = inv.hosts[host_id]
            sid = software_id(h["site"], host_id, p.name, p.version)
            software.append(
                {
                    "software_id": sid,
                    "asset_id": host_id,
                    "asset_name": h["name"],
                    "site": h["site"],
                    "product": p.name,
                    "version": p.version,
                    "cpe": used_cpe,
                    "cpe_product": cpe_product(used_cpe),
                    "match_basis": basis,
                    "status": status,
                    "reason": reason,
                    "cve_count": len(kept),
                    "max_cvss": max(scores) if scores else None,
                    "kev_count": sum(1 for c in kept if c["kev"]),
                }
            )
            for cve in kept:
                rows.append(
                    {
                        "site": h["site"],
                        "asset_id": host_id,
                        "software_id": sid,
                        "asset_name": h["name"],
                        "ips": h["ips"],
                        "product": p.name,
                        "version": p.version,
                        "cpe": used_cpe,
                        "cpe_product": cpe_product(used_cpe),
                        "match_basis": basis,
                        "cve_id": cve["id"],
                        "cvss_score": cve["score"],
                        "severity": cve["severity"],
                        "kev": cve["kev"],
                        "published": cve["published"],
                        "description": cve["description"],
                    }
                )
    rows.sort(key=lambda r: (-(r["cvss_score"] or 0), r["asset_name"], r["cve_id"]))
    software.sort(key=lambda r: (r["asset_name"].lower(), r["product"].lower(), r["version"]))
    return rows, unmapped, software


# ==========================================================================
# Output
# ==========================================================================


## @brief Neutralise spreadsheet formula injection in a CSV cell.
#  @details Software names and CVE text are third-party data; a cell that
#  starts with `=`, `+`, `-` or `@` could run as a formula in Excel.
def _csv_safe(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@"):
        return "'" + value
    return value


## @brief Write a list of dict rows as CSV.
def write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({c: _csv_safe(r.get(c)) for c in columns})


## @brief Write the findings (CSV + JSON), the software inventory (CSV + JSON) and the unmapped list.
#  @return The paths: findings CSV, findings JSON, unmapped CSV, software CSV, software JSON.
def write_outputs(
    out_dir: Path, stamp: str, rows: list[dict[str, Any]], unmapped: list[dict[str, Any]], software: list[dict[str, Any]]
) -> tuple[Path, Path, Path, Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / f"sbom_cves_{stamp}.csv"
    json_path = out_dir / f"sbom_cves_{stamp}.json"
    un_path = out_dir / f"sbom_unmapped_{stamp}.csv"
    sw_csv = out_dir / f"sbom_software_{stamp}.csv"
    sw_json = out_dir / f"sbom_software_{stamp}.json"
    write_csv(csv_path, REPORT_COLUMNS, rows)
    json_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    write_csv(un_path, UNMAPPED_COLUMNS, unmapped)
    write_csv(sw_csv, SOFTWARE_COLUMNS, software)
    sw_json.write_text(json.dumps(software, indent=2), encoding="utf-8")
    return csv_path, json_path, un_path, sw_csv, sw_json


# ==========================================================================
# Suggesting mappings for unmapped products (`suggest-map`)
# ==========================================================================

## @brief Product-name prefixes that identify a vendor: `(regex on the lower-case cleaned name,
#  display name, NVD CPE vendor string)`.
#  @details Windows reports no publisher, so the vendor has to be read from the name. The
#  CPE vendor strings are *hints*: `suggest_mappings()` only proposes a mapping when the
#  NVD's own CPE dictionary confirms a product for that vendor. First match wins.
VENDOR_HINTS: list[tuple[str, str, str]] = [
    (r"^(microsoft|windows|visual (c\+\+|basic|f#|j#|studio)|sql server|msxml|\.net|wcf |typescript|sharepoint|team explorer|team foundation)", "Microsoft", "microsoft"),
    (r"^(siemens|simatic|tia |totally integrated|step ?7|wincc|digsi|sigra|s7-)", "Siemens", "siemens"),
    (r"^(rockwell|factorytalk|rslogix|rslinx|rsnetworx|studio 5000|logix|ccw |controlflash|guardmaster|bulletin|allen)", "Rockwell Automation", "rockwellautomation"),
    (r"^abb\b", "ABB", "abb"),
    (r"^(ni[ -]|labview|labwindows|visa )", "National Instruments", "ni"),
    (r"^(schneider|ecostruxure|unity|se )", "Schneider Electric", "schneider-electric"),
    (r"^python", "Python Software Foundation", "python"),
    (r"^adobe", "Adobe", "adobe"),
    (r"^mcafee", "McAfee", "mcafee"),
    (r"^(vnc|realvnc)", "RealVNC", "realvnc"),
    (r"^vmware", "VMware", "vmware"),
    (r"^forti", "Fortinet", "fortinet"),
    (r"^codesys", "CODESYS", "codesys"),
    (r"^(deltav|emerson)", "Emerson", "emerson"),
    (r"^zebra", "Zebra Technologies", "zebra"),
    (r"^fanuc", "FANUC", "fanuc"),
    (r"^canon", "Canon", "canon"),
    (r"^google", "Google", "google"),
    (r"^tenable", "Tenable", "tenable"),
    (r"^opc ", "OPC Foundation", "opcfoundation"),
    (r"^pkzip", "PKWARE", "pkware"),
]


## @brief Key under which a product name is looked up in a vendor file: cleaned, lower-case, no trailing version.
def _vendor_key(name: str, version: str = "") -> str:
    return re.sub(r"\s+v?\d+(?:\.\d+)+$", "", clean_name(name, version).lower()).strip()


## @brief Load a vendor file: your own `product name -> vendor` list.
#  @details Windows reports no publisher, so vendors for products the built-in name prefixes do
#  not recognise can be supplied here. A CSV or tab-separated file with a header row; the
#  columns are `Title` (or `product`) and `Vendor`. A trailing version in the title is ignored.
#  The vendor is used as the BOM supplier (marked as coming from this file) and as the vendor
#  shown by `suggest-map`.
#  @param path File path, or `None`.
#  @return `{lookup key: vendor name}`.
#  @throws ExportError If the file cannot be read or lacks the columns.
def load_vendor_file(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError as e:
        raise ExportError(f"--vendor-file {path!r} could not be read: {e}") from e
    first = text.splitlines()[0] if text.strip() else ""
    rows = list(csv.DictReader(text.splitlines(), delimiter="\t" if "\t" in first else ","))
    cols = {(k or "").strip().lower(): k for k in (rows[0] if rows else {})}
    tcol = cols.get("title") or cols.get("product")
    vcol = cols.get("vendor")
    if rows and not (tcol and vcol):
        raise ExportError(f"--vendor-file {path!r} needs a header row with Title (or product) and Vendor columns.")
    return {_vendor_key(r[tcol]): r[vcol].strip() for r in rows if (r.get(tcol) or "").strip() and (r.get(vcol) or "").strip()}


## @brief Which vendor file to use: `--vendor-file`, else `TENABLE_VENDOR_FILE`, else `vendors.tsv` next to the script or in the current folder.
#  @param arg The `--vendor-file` value; `none` switches the vendor file off.
#  @return The path, or `None` when there is no vendor file.
def find_vendor_file(arg: str | None) -> str | None:
    choice = arg if arg is not None else os.environ.get("TENABLE_VENDOR_FILE", "")
    if choice.strip().lower() == "none":
        return None
    if choice.strip():
        return choice
    for folder in (Path(__file__).resolve().parent, Path.cwd()):
        candidate = folder / "vendors.tsv"
        if candidate.is_file():
            log(f"Using vendor file {candidate} (switch off with --vendor-file none).")
            return str(candidate)
    return None


## @brief The vendor hint for a cleaned product name, or `None`.
#  @param vendors Your vendor file (see `load_vendor_file()`), used when no built-in prefix matches.
#  @return `(display name, CPE vendor)`; the CPE vendor is empty for a vendor-file entry.
def vendor_hint(cleaned: str, vendors: dict[str, str] | None = None) -> tuple[str, str] | None:
    low = cleaned.lower()
    for pattern, display, cpe_vendor in VENDOR_HINTS:
        if re.search(pattern, low):
            return display, cpe_vendor
    named = (vendors or {}).get(_vendor_key(cleaned))
    return (named, "") if named else None   # from your vendor file: no CPE vendor string known


## @brief Lower-case a name and keep only letters and digits, so `visual_c++_2013` and `Visual C++ 2013` compare equal.
def _alnum(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


## @brief Choose the NVD product that a product name is confirmed to be.
#  @details A candidate counts only if its product string appears in the name (ignoring
#  punctuation) and, when the name has a vendor hint, the candidate's vendor is that
#  vendor. The longest product string wins, so `sql_server_compact` beats `sql_server`.
#  @param name Cleaned product name.
#  @param hint The vendor hint's CPE vendor, or `None`.
#  @param candidates `(vendor, product)` pairs from the NVD CPE dictionary.
#  @return `(vendor, product, confidence)` where confidence is `"high"` (vendor hinted and
#          confirmed) or `"medium"` (no hint; the vendor is whatever the NVD lists); or `None`.
def suggest_pick(name: str, hint: str | None, candidates: list[tuple[str, str]]) -> tuple[str, str, str] | None:
    flat = _alnum(name)
    best: tuple[str, str] | None = None
    for vendor, product in candidates:
        if hint and vendor != hint:
            continue
        p = _alnum(product)
        if len(p) >= 3 and p in flat and (best is None or len(p) > len(_alnum(best[1]))):
            best = (vendor, product)
    if best is None:
        return None
    return best[0], best[1], "high" if hint else "medium"


## @brief Read the unmapped report (`sbom_unmapped_*.csv`).
#  @return Rows with `product`, `version`, `reason` and `hosts`.
#  @throws ExportError If the file is missing or lacks those columns.
def read_unmapped(path: str) -> list[dict[str, str]]:
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    except OSError as e:
        raise ExportError(f"Cannot read {path!r}: {e}") from e
    if rows and not {"product", "version", "reason"} <= set(rows[0]):
        raise ExportError(f"{path!r} is not an unmapped-products report (needs product, version, reason columns).")
    return [{**r, "product": r["product"].lstrip("'")} for r in rows]   # undo the CSV formula guard


## @brief Propose `(vendor, product)` mappings for unmapped products, checked against the NVD.
#  @details Products with the same cleaned name are one group. For each group the NVD CPE
#  dictionary is searched with the full name and then its first three words. A mapping is
#  proposed only when `suggest_pick()` confirms it; anything else is reported with the
#  reason (and the vendor hint, which is useful on its own). Nothing is guessed.
#  @param rows Rows from `read_unmapped()`; only `no CPE mapping` rows are considered.
#  @param nvd NVD client, or `None` for a dry run (vendor hints only).
#  @param vendors Your vendor file, for products the built-in prefixes do not recognise.
#  @return `(suggestions, review)`: a map-file dict `{regex: [vendor, product]}`, and one review row per group.
def suggest_mappings(
    rows: list[dict[str, str]], nvd: NvdClient | None, vendors: dict[str, str] | None = None
) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    groups: dict[str, dict[str, Any]] = {}
    for r in rows:
        if r["reason"] != "no CPE mapping":
            continue
        name = clean_name(r["product"], r["version"])
        g = groups.setdefault(name.lower(), {"name": name, "versions": set(), "hosts": 0})
        g["versions"].add(r["version"])
        g["hosts"] += int(r.get("hosts") or 0)
    suggestions: dict[str, list[str]] = {}
    review: list[dict[str, Any]] = []
    for i, (key, g) in enumerate(sorted(groups.items()), 1):
        hint = vendor_hint(g["name"], vendors)
        row = {
            "product": g["name"], "versions": " | ".join(sorted(g["versions"]))[:200], "hosts": g["hosts"],
            "vendor_hint": hint[0] if hint else "", "proposed_vendor": "", "proposed_product": "",
            "confidence": "", "status": "", "nvd_candidates": "",
            "fragment_hint": "likely build fragment: consider leaving unmapped, or map to the parent product" if _FRAGMENT_RE.search(g["name"]) else "",
        }
        if nvd is None:
            row["status"] = "dry_run" if hint else "unknown_vendor"
        else:
            seen: list[tuple[str, str]] = []
            pick = None
            for query in dict.fromkeys((" ".join(g["name"].split()[:6]), " ".join(g["name"].split()[:3]))):
                for pair in nvd.keyword_candidates(query):
                    if pair not in seen:
                        seen.append(pair)
                pick = suggest_pick(g["name"], (hint[1] or None) if hint else None, seen)
                if pick:
                    break
            row["nvd_candidates"] = "; ".join(f"{v}:{p}" for v, p in seen[:6])
            if pick:
                row.update(proposed_vendor=pick[0], proposed_product=pick[1], confidence=pick[2], status="suggested")
                suggestions["^" + re.escape(key)] = [re.sub(r"\\(.)", r"\1", pick[0]), re.sub(r"\\(.)", r"\1", pick[1])]
            else:
                row["status"] = "vendor_known_no_nvd_product" if hint else "unknown_vendor"
            log(f"  [{i}/{len(groups)}] {g['name']} -> {row['status']}" + (f" ({pick[0]}:{pick[1]})" if pick else ""))
        review.append(row)
    return suggestions, review


## @brief `suggest-map`: write a draft mapping file and a review sheet for unmapped products.
#  @param args Parsed arguments: `unmapped` (CSV path), `out_dir`, `cache_dir`, `dry_run`.
#  @return 0 on success.
def run_suggest_map(args: argparse.Namespace) -> int:
    rows = read_unmapped(args.unmapped)
    nvd = None
    if not args.dry_run:
        nvd = NvdClient(os.environ.get("NVD_API_KEY", "").strip(), DiskCache(Path(args.cache_dir) / "nvd_cache.json"))
        if not nvd.api_key:
            log("Note: no NVD_API_KEY set; this makes up to two NVD requests per product group, one per ~6.5 s. A free key makes it ~10x faster.")
    try:
        suggestions, review = suggest_mappings(rows, nvd, load_vendor_file(find_vendor_file(args.vendor_file)))
    finally:
        if nvd:
            nvd.cache.save()
    n = len(review)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    review_path = out / f"sbom_mapping_review_{stamp}.csv"
    write_csv(review_path, ["product", "versions", "hosts", "vendor_hint", "proposed_vendor", "proposed_product", "confidence", "status", "fragment_hint", "nvd_candidates"], review)
    paths = [review_path]
    if nvd is not None:
        map_path = out / f"sbom_mapping_suggestions_{stamp}.json"
        map_path.write_text(json.dumps(suggestions, indent=2, sort_keys=True), encoding="utf-8")
        paths.append(map_path)
    known = sum(1 for r in review if r["vendor_hint"])
    print(f"{n} product group(s); vendor recognised for {known}; " + (f"{len(suggestions)} mapping(s) confirmed in the NVD." if nvd else "dry run: nothing sent to the NVD."))
    print("  " + "\n  ".join(str(p) for p in paths))
    if nvd is not None:
        print("Review the sheet, delete any wrong entries from the JSON, then run: sbom --map-file <that json>")
    return 0


# ==========================================================================
# CycloneDX output
# ==========================================================================

## @brief Severity words CycloneDX accepts in a vulnerability rating.
_CDX_SEVERITIES = {"critical", "high", "medium", "low", "info", "none"}


## @brief Make a stored NVD date (`2024-03-01`) or UTC timestamp a valid CycloneDX date-time.
def _cdx_time(text: str) -> str:
    if re.fullmatch(r"\d{4}-\d\d-\d\d", text):
        return text + "T00:00:00Z"
    return text if re.search(r"(Z|[+-]\d\d:?\d\d)$", text) else text + "Z"


## @brief Default name of the root component a BOM describes.
DEFAULT_PRODUCT_NAME = "Tenable OT installed-software inventory"


## @brief Turn `Name <email>`, a bare name or a URL into a CycloneDX contact (or `None` when empty).
def parse_author(text: str) -> dict[str, str] | None:
    text = (text or "").strip()
    if not text:
        return None
    m = re.fullmatch(r"(.*?)\s*<([^<>@\s]+@[^<>\s]+)>", text)
    if m:
        contact = {"name": m.group(1)} if m.group(1) else {}
        contact["email"] = m.group(2)
        return contact
    return {"name": text}


## @brief Build a CycloneDX 1.6 BOM from the scan results.
#  @details Model: each host is a `device` component and each distinct product version
#  (name, version, CPE) is one `application` component, joined by `dependencies` (host
#  depends on its software). Each CVE is one entry in `vulnerabilities` that `affects`
#  every product version it was matched to, with `analysis.state` = `in_triage`: the
#  match is inferred from names and versions and nobody has verified it. The BOM holds
#  host names and IP addresses, so treat the file like the CSV reports. Licences and
#  hashes are not known to Tenable OT and are not included.
#  @param software Inventory rows from `build_report()`.
#  @param rows Finding rows from `build_report()`.
#  @param hosts `Inventory.hosts`: asset id -> name, site, IPs.
#  @param stamp UTC timestamp for `metadata.timestamp` (ISO 8601).
#  @param serial A `urn:uuid:` serial number (a parameter so tests are deterministic).
#  @param vendors Your vendor file; a match becomes the component's `supplier` and `manufacturer`, marked `supplier_basis=vendor_file`.
#  @param author Who is responsible for the SBOM: `Name <email>`, or a name or URL. Omitted from the BOM when empty.
#  @param product_name What the BOM describes (the root `metadata.component`).
#  @param product_version Version of that description (defaults to the BOM's date).
#  @return The BOM as a JSON-ready dict. The root component depends on every host, the host on its software.
def build_cyclonedx(
    software: list[dict[str, Any]], rows: list[dict[str, Any]], hosts: dict[str, dict[str, str]], stamp: str, serial: str,
    vendors: dict[str, str] | None = None, author: str = "", product_name: str = DEFAULT_PRODUCT_NAME,
    product_version: str = "", descriptions: bool = True,
) -> dict[str, Any]:
    def sw_ref(product: str, version: str, cpe: str) -> str:
        return "sw-" + hashlib.sha256("\x1f".join((product, version, cpe)).encode("utf-8")).hexdigest()[:16]

    apps: dict[str, dict[str, Any]] = {}
    deps: dict[str, set[str]] = {}
    for r in software:
        ref = sw_ref(r["product"], r["version"], r["cpe"])
        if ref not in apps:
            comp: dict[str, Any] = {"type": "application", "bom-ref": ref, "name": r["product"]}
            if r["version"]:
                comp["version"] = r["version"]
            if r["cpe"]:
                comp["cpe"] = r["cpe"]
            comp["properties"] = [{"name": "t1ote:status", "value": r["status"]}]
            supplier = (vendors or {}).get(_vendor_key(r["product"], r["version"]))
            if supplier:                      # a claim by whoever wrote the vendor file, not by Tenable
                comp["supplier"] = {"name": supplier}
                comp["manufacturer"] = {"name": supplier}
                comp["properties"].append({"name": "t1ote:supplier_basis", "value": "vendor_file"})
            if r["match_basis"]:
                comp["properties"].append({"name": "t1ote:match_basis", "value": r["match_basis"]})
            apps[ref] = comp
        deps.setdefault("asset-" + r["asset_id"], set()).add(ref)

    devices = []
    for aid in sorted(hosts):
        if "asset-" + aid not in deps:
            continue
        h = hosts[aid]
        props = [{"name": "t1ote:site", "value": h["site"]}, {"name": "t1ote:asset_id", "value": aid}]
        if h["ips"]:
            props.append({"name": "t1ote:ips", "value": h["ips"]})
        devices.append({"type": "device", "bom-ref": "asset-" + aid, "name": h["name"] or aid, "properties": props})

    vulns: dict[str, dict[str, Any]] = {}
    for r in rows:
        v = vulns.get(r["cve_id"])
        if v is None:
            sev = (r["severity"] or "").lower()
            rating: dict[str, Any] = {"source": {"name": "NVD"}, "severity": sev if sev in _CDX_SEVERITIES else "unknown", "method": "other"}
            if r["cvss_score"] is not None:
                rating["score"] = r["cvss_score"]
            v = {
                "id": r["cve_id"],
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{r['cve_id']}"},
                "ratings": [rating],
                "analysis": {"state": "in_triage", "detail": "Inferred from product name and version; not verified."},
                "affects": [],
            }
            if descriptions and r["description"]:
                v["description"] = r["description"]
            if r["published"]:
                v["published"] = _cdx_time(r["published"])
            if r["kev"]:
                v["properties"] = [{"name": "cisa:kev", "value": "true"}]
            vulns[r["cve_id"]] = v
        ref = sw_ref(r["product"], r["version"], r["cpe"])
        if not any(a["ref"] == ref for a in v["affects"]):
            v["affects"].append({"ref": ref})

    root_ref = "product-root"
    metadata: dict[str, Any] = {
        "timestamp": stamp,
        "lifecycles": [{"phase": "operations"}],
        "component": {
            "type": "platform", "bom-ref": root_ref, "name": product_name or DEFAULT_PRODUCT_NAME,
            "version": product_version or stamp[:10],
        },
    }
    contact = parse_author(author)
    if contact:
        metadata["authors"] = [contact]
    metadata["tools"] = {"components": [{"type": "application", "name": "t1ote_export_assets", "version": hx.__version__}]}
    metadata["properties"] = [
        {"name": "t1ote:note", "value": "Software inferred from Tenable OT asset data; vulnerability matches are inferred from product names and versions."}
    ]
    dependencies = [{"ref": root_ref, "dependsOn": sorted(d["bom-ref"] for d in devices)}]
    dependencies += [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(deps.items())]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": metadata,
        # What we know we cannot see: only Windows installed-software lists, with noise packages dropped.
        "compositions": [{"aggregate": "incomplete", "assemblies": [root_ref]}],
        "components": devices + [apps[k] for k in sorted(apps, key=lambda k: (apps[k]["name"].lower(), apps[k].get("version", "")))],
        "dependencies": dependencies,
        "vulnerabilities": sorted(vulns.values(), key=lambda v: v["id"]),
    }


## @brief Write the CycloneDX BOM next to the other reports.
#  @return The file written (`sbom_cyclonedx_<stamp>.json`).
def write_cyclonedx(
    out_dir: Path, stamp: str, software: list[dict[str, Any]], rows: list[dict[str, Any]], hosts: dict[str, dict[str, str]],
    vendors: dict[str, str] | None = None, author: str = "", product_name: str = DEFAULT_PRODUCT_NAME,
    product_version: str = "", descriptions: bool = True,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"sbom_cyclonedx_{stamp}.json"
    iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.write_text(json.dumps(build_cyclonedx(software, rows, hosts, iso, f"urn:uuid:{uuid.uuid4()}", vendors, author, product_name, product_version, descriptions), separators=(",", ":")), encoding="utf-8")
    return path


# ==========================================================================
# Collecting from every target and site
# ==========================================================================


## @brief Read one site (or standalone ICP) into the shared inventory.
#  @details Tries the server-side "Windows hosts only" filter first and, if the
#  server rejects it before returning anything, retries without it.
#  @param inv Inventory to add to.
#  @param tenable Client for the target.
#  @param site_id Site machine id, or `None` for a standalone ICP.
#  @param site_label Name recorded in the `site` column.
#  @param base_filter Scope filter from the command line (or `None`).
#  @param args Parsed arguments (`all_os`, `page_size`, `limit`, `keep_noise`).
def collect_site(
    inv: Inventory, tenable: hx.Tenable, site_id: str | None, site_label: str, base_filter: dict | None, args: argparse.Namespace
) -> None:
    windows_filter = base_filter if args.all_os else with_windows_clause(base_filter)
    before = inv.assets_scanned
    try:
        collect_inventory(
            with_full_details(tenable, site_id, iter_assets(tenable, site_id, windows_filter, args.page_size, args.limit)),
            args.keep_noise,
            site_label,
            inv,
        )
    except ExportError as e:
        if args.all_os or inv.assets_scanned != before:
            raise  # only a rejection before any asset was read means "the OS filter is unsupported"
        # The server-side OS filter is the only unverified part of the query;
        # fall back to scanning every asset and skipping non-hosts client-side.
        log(f"  OS filter was rejected ({e}); retrying without it.")
        collect_inventory(
            with_full_details(tenable, site_id, iter_assets(tenable, site_id, base_filter, args.page_size, args.limit)),
            args.keep_noise,
            site_label,
            inv,
        )


# ==========================================================================
# Power BI output (reuses the sign-in and push-dataset client in t1ote_core)
# ==========================================================================

## @brief Power BI table holding one row per product version on a host (the inventory).
SOFTWARE_TABLE = "sbom_software"
## @brief Power BI table holding one row per CVE finding.
FINDINGS_TABLE = "sbom_findings"

## @brief Schema of `sbom_software` as `(column, Power BI type)`.
SBOM_SOFTWARE_COLUMNS = [
    ("software_id", "string"),
    ("asset_id", "string"),
    ("asset_name", "string"),
    ("site", "string"),
    ("product", "string"),
    ("version", "string"),
    ("cpe", "string"),
    ("cpe_product", "string"),
    ("match_basis", "string"),
    ("status", "string"),
    ("reason", "string"),
    ("cve_count", "Int64"),
    ("max_cvss", "Double"),
    ("kev_count", "Int64"),
    ("exported_at", "DateTime"),
]

## @brief Schema of `sbom_findings` as `(column, Power BI type)`.
SBOM_FINDINGS_COLUMNS = [
    ("software_id", "string"),
    ("asset_id", "string"),
    ("site", "string"),
    ("asset_name", "string"),
    ("ips", "string"),
    ("product", "string"),
    ("version", "string"),
    ("cpe", "string"),
    ("cpe_product", "string"),
    ("match_basis", "string"),
    ("cve_id", "string"),
    ("cvss_score", "Double"),
    ("severity", "string"),
    ("kev", "Boolean"),
    ("published", "string"),
    ("description", "string"),
    ("exported_at", "DateTime"),
]


## @brief PostgreSQL definitions of the two SBOM tables (same columns as Power BI).
def sql_tables() -> tuple[sq.Table, sq.Table]:
    software = sq.Table(SOFTWARE_TABLE, list(SBOM_SOFTWARE_COLUMNS), key=("software_id",), indexes=("asset_id", "cpe_product"))
    findings = sq.Table(
        FINDINGS_TABLE, list(SBOM_FINDINGS_COLUMNS), key=("software_id", "cve_id"), indexes=("asset_id", "cve_id", "cpe_product"),
    )
    return software, findings


## @brief The export tool's Power BI client, creating one dataset with all three tables.
#  @details The `assets` table (filled by `t1ote_export_assets.py assets --powerbi`) and the two SBOM
#  tables share a dataset so Power BI can relate them:
#  `assets[asset_id] 1-* sbom_software[asset_id]` and
#  `sbom_software[software_id] 1-* sbom_findings[software_id]`.
class SbomPowerBI(hx.PowerBI):
    ## @brief Create the push dataset.
    #  @param relationships Also define the two relationships. If Power BI rejects
    #         them, retry without and add them in the model view.
    #  @param columns Columns of the `assets` table (see `hx.resolve_columns()`).
    #  @return The new dataset's GUID.
    #  @throws ExportError On any Power BI failure.
    def create_dataset(self, columns: list[hx.Column], relationships: bool = True) -> str:
        assets = self.cfg.table_name
        asset_schema = [(c.name, c.dtype) for c in columns]
        body: dict[str, Any] = {
            "name": self.cfg.dataset_name,
            "defaultMode": "Push",
            "tables": [
                {"name": assets, "columns": [{"name": n, "dataType": t} for n, t in asset_schema]},
                {"name": SOFTWARE_TABLE, "columns": [{"name": n, "dataType": t} for n, t in SBOM_SOFTWARE_COLUMNS]},
                {"name": FINDINGS_TABLE, "columns": [{"name": n, "dataType": t} for n, t in SBOM_FINDINGS_COLUMNS]},
            ],
        }
        if relationships:
            body["relationships"] = [
                {"name": "assets_to_software", "fromTable": SOFTWARE_TABLE, "fromColumn": "asset_id",
                 "toTable": assets, "toColumn": "asset_id", "crossFilteringBehavior": "OneDirection"},
                {"name": "software_to_findings", "fromTable": FINDINGS_TABLE, "fromColumn": "software_id",
                 "toTable": SOFTWARE_TABLE, "toColumn": "software_id", "crossFilteringBehavior": "OneDirection"},
            ]
        url = self._url("/datasets") + "?defaultRetentionPolicy=basicFIFO"
        return self._call("POST", url, "creating the dataset", json=body).json()["id"]

    ## @brief Replace the contents of one table.
    #  @param table Table name in the dataset.
    #  @param rows Row dicts matching that table's schema.
    #  @return The number of push requests sent.
    #  @throws ExportError On any Power BI failure.
    def replace_table(self, table: str, rows: list[dict[str, Any]]) -> int:
        url = self._url(f"/datasets/{self.cfg.dataset_id}/tables/{table}/rows")
        self._call("DELETE", url, f"clearing table {table!r}")
        batches = 0
        for i in range(0, len(rows), hx.PUSH_BATCH_ROWS):
            chunk = rows[i : i + hx.PUSH_BATCH_ROWS]
            self._call("POST", url, f"pushing {table} rows {i + 1}-{i + len(chunk)}", json={"rows": chunk})
            batches += 1
        return batches


## @brief Power BI settings (shared with the asset export: one dataset, one `POWERBI_DATASET_ID`).
#  @param need_dataset True when rows will be written (the dataset id is required).
#  @return A `PowerBIConfig`; its `table_name` is the assets table.
#  @throws ExportError If a required setting is missing.
def sbom_powerbi_config(need_dataset: bool) -> hx.PowerBIConfig:
    if need_dataset and not os.environ.get("POWERBI_DATASET_ID", "").strip():
        raise ExportError(
            "POWERBI_DATASET_ID is not set. Run `python t1ote_export_assets.py create-dataset` once and "
            "add the line it prints to your .env file."
        )
    base = hx.PowerBIConfig.from_env(need_dataset=False)
    name = os.environ.get("POWERBI_DATASET_NAME", "").strip() or "Tenable OT Assets and SBOM"
    return dataclasses.replace(base, dataset_name=name)


## @brief Shape rows for a Power BI table.
#  @details Keeps exactly the schema columns, adds `exported_at`, and omits a
#  `None` number so Power BI stores an empty value, not 0. CSV formula-escaping is
#  *not* applied: these rows never reach a spreadsheet cell.
#  @param rows Report or software rows.
#  @param columns The table schema.
#  @param exported_at UTC timestamp for the `exported_at` column.
def _powerbi_table_rows(rows: list[dict[str, Any]], columns: list[tuple[str, str]], exported_at: str) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        d: dict[str, Any] = {}
        for name, kind in columns:
            if name == "exported_at":
                d[name] = exported_at
                continue
            v = r.get(name)
            if v is None and kind in ("Double", "Int64"):
                continue
            d[name] = bool(v) if kind == "Boolean" else v
        out.append(d)
    return out


## @brief Findings rows for `sbom_findings`.
def powerbi_rows(rows: list[dict[str, Any]], exported_at: str) -> list[dict[str, Any]]:
    return _powerbi_table_rows(rows, SBOM_FINDINGS_COLUMNS, exported_at)


## @brief Inventory rows for `sbom_software`.
def powerbi_software_rows(software: list[dict[str, Any]], exported_at: str) -> list[dict[str, Any]]:
    return _powerbi_table_rows(software, SBOM_SOFTWARE_COLUMNS, exported_at)


## @brief Add the SBOM-specific options.
def add_sbom_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("software / CVE lookup")
    g.add_argument("--all-os", action="store_true", help="Do not restrict to Windows hosts (slower; non-Windows assets carry no software list).")
    g.add_argument("--page-size", type=int, default=SBOM_PAGE_SIZE, help=f"Assets per Tenable request when reading software (default {SBOM_PAGE_SIZE}; each Windows host is ~80 KB).")
    g.add_argument("--keep-noise", action="store_true", help="Keep EDS/module-profile/SDK-pack entries (normally dropped).")
    g.add_argument("--map-file", help="JSON file of extra mappings: {regex: [vendor, product]}.")
    g.add_argument("--fuzzy", action="store_true", help="For unknown products, try an NVD keyword search (more matches, more false positives).")
    g.add_argument("--min-cvss", type=float, default=0.0, help="Drop CVEs scored below this (unscored CVEs are kept).")
    g.add_argument("--kev-only", action="store_true", help="Keep only CVEs in CISA's Known Exploited Vulnerabilities list.")
    g.add_argument("--vendor-file", metavar="FILE", help="CSV/TSV with Title and Vendor columns: your own product -> vendor list, used as the CycloneDX supplier (marked as user-supplied). Default: env TENABLE_VENDOR_FILE, else vendors.tsv next to the script or in the current folder; `none` turns it off.")
    g.add_argument("--sbom-author", metavar="TEXT", help="Who is responsible for the CycloneDX SBOM: 'Name <email>' or a name/URL (env SBOM_AUTHOR). Omitted from the BOM if not set.")
    g.add_argument("--product-name", metavar="TEXT", help=f"What the CycloneDX BOM describes, e.g. your site or system (env SBOM_PRODUCT_NAME; default '{DEFAULT_PRODUCT_NAME}').")
    g.add_argument("--product-version", metavar="TEXT", help="Version of that description (env SBOM_PRODUCT_VERSION; default: the BOM's date).")
    g.add_argument("--cyclonedx", action="store_true", help="Also write the results as a CycloneDX 1.6 BOM (hosts, software and vulnerabilities; contains host names and IPs). Written compact (no indentation) to keep it small.")
    g.add_argument("--cyclonedx-no-descriptions", action="store_true", help="Leave the CVE descriptions out of the CycloneDX file (each entry still links to the NVD). Use if a tool rejects a file over its size limit.")
    g.add_argument("--cache-dir", default=".sbom_cache", help="NVD answer cache (default ./.sbom_cache; entries expire after 7 days).")


## @brief Collect software, look up CVEs, write the report (and optionally push it to Power BI).
#  @param args Parsed arguments: connection, scope, SBOM and output options (see `add_sbom_args`).
#  @return 0 on success.
#  @throws ExportError On invalid options or any Tenable / NVD / Power BI failure.
def run_sbom(args: argparse.Namespace) -> int:
    if args.limit is not None and args.limit < 1:
        raise ExportError("--limit must be a positive number.")
    if not 1 <= args.page_size <= 100:
        raise ExportError("--page-size must be between 1 and 100.")
    base_filter = hx.build_filter(args.criticality_at_least, args.subnet, args.ip_range)
    user_map = load_map_file(args.map_file)
    targets = hx.load_targets(args)

    # Check Power BI settings now, so a missing dataset id fails before a long NVD run.
    pbi = SbomPowerBI(sbom_powerbi_config(need_dataset=True)) if args.powerbi and not args.dry_run else None

    log("Collecting installed software from Tenable...")
    inv = Inventory()
    for cfg in targets:
        tenable = hx.Tenable(cfg)
        for site_id, site_label in tenable.sites_to_scan():
            log(f"Site: {site_label}" + (f" ({site_id})" if site_id else " (standalone ICP)"))
            collect_site(inv, tenable, site_id, site_label, base_filter, args)

    log(
        f"{inv.assets_scanned} asset(s) scanned, {inv.assets_with_wmi} reported WMI data, {inv.assets_with_software} with software; "
        f"{inv.items_seen} entries, {inv.noise_dropped} dropped as non-product data, "
        f"{len(inv.products)} distinct product versions."
    )

    cache_dir = Path(args.cache_dir)
    nvd = NvdClient(os.environ.get("NVD_API_KEY", "").strip(), DiskCache(cache_dir / "nvd_cache.json"))
    try:
        resolve_products(inv, user_map, nvd if not args.dry_run else None, args.fuzzy)
    finally:
        nvd.cache.save()  # keep keyword searches even if the run is interrupted
    mapped = sum(1 for p in inv.products.values() if p.cpe)
    log(f"{mapped} of {len(inv.products)} product versions mapped to a CPE.")

    if args.dry_run:
        if args.powerbi:
            log("Dry run: nothing is pushed to Power BI.")
        print(f"[dry run] {mapped} product version(s) would be looked up in the NVD. Mapped:")
        for p in sorted((p for p in inv.products.values() if p.cpe), key=lambda p: p.name.lower())[:25]:
            print(f"  {p.name} {p.version} -> {p.cpe} [{p.basis}] on {len(p.hosts)} host(s)")
        print(f"Unmapped: {len(inv.products) - mapped} (first 10):")
        for p in sorted((p for p in inv.products.values() if not p.cpe), key=lambda p: p.name.lower())[:10]:
            print(f"  {p.name} {p.version}: {p.reason}")
        return 0

    if not nvd.api_key:
        log("Note: no NVD_API_KEY set; lookups are limited to one request per ~6.5 s. A free key makes this ~10x faster.")
    log("Looking up CVEs in the NVD (cached results are reused)...")
    try:
        rows, unmapped, software = build_report(inv, nvd, args.min_cvss, args.kev_only)
    finally:
        nvd.cache.save()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    paths = list(write_outputs(Path(args.out_dir), stamp, rows, unmapped, software))
    if args.cyclonedx:
        paths.append(write_cyclonedx(
            Path(args.out_dir), stamp, software, rows, inv.hosts, load_vendor_file(find_vendor_file(args.vendor_file)),
            args.sbom_author or os.environ.get("SBOM_AUTHOR", ""), args.product_name or os.environ.get("SBOM_PRODUCT_NAME", "") or DEFAULT_PRODUCT_NAME,
            args.product_version or os.environ.get("SBOM_PRODUCT_VERSION", ""), not args.cyclonedx_no_descriptions,
        ))
    crit = sum(1 for r in rows if (r["cvss_score"] or 0) >= 9)
    kev = sum(1 for r in rows if r["kev"])
    print(
        f"Done: {len(software)} software row(s) on {len(inv.hosts)} host(s); {len(rows)} finding(s) across "
        f"{len({r['asset_id'] for r in rows})} host(s) ({crit} critical-scored, {kev} known-exploited). "
        f"{len(unmapped)} product(s) not mapped."
    )
    print("  " + "\n  ".join(str(x) for x in paths))
    print("Results are inferred from product names and versions; verify before acting.")

    if pbi is not None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            log(f"Replacing Power BI tables {SOFTWARE_TABLE!r} ({len(software)} rows) and {FINDINGS_TABLE!r} ({len(rows)} rows)...")
            b1 = pbi.replace_table(SOFTWARE_TABLE, powerbi_software_rows(software, ts))  # parent first
            b2 = pbi.replace_table(FINDINGS_TABLE, powerbi_rows(rows, ts))
        except ExportError as e:
            raise ExportError(f"The report files above were written, but the Power BI push failed: {e}") from e
        print(f"Power BI: {len(software)} software row(s) and {len(rows)} finding(s) written ({b1 + b2} batch(es)).")
    sink = getattr(args, "sink", None)
    if sink is not None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        t_software, t_findings = sql_tables()
        t_findings.after.append(sq.exposure_view(sink.schema))
        try:
            log(f"Replacing PostgreSQL tables {t_software.name!r} and {t_findings.name!r}...")
            n1 = sink.replace_table(t_software, powerbi_software_rows(software, ts))  # parent first
            n2 = sink.replace_table(t_findings, powerbi_rows(rows, ts))
            sink.checkpoint()
        except Exception as e:
            raise ExportError(f"The report files above were written, but the PostgreSQL write failed (nothing was changed): {e}") from e
        print(f"PostgreSQL: {n1} software row(s) and {n2} finding(s) written to schema {sink.schema!r}" + (f"; script {args.sql_out}" if args.sql_out else "") + ".")
    return 0
