#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
## @file t1ote_core.py
#  @brief Shared library for the Tenable One OT Exposure export tool (no command line here).
#
#  @details
#  This module holds everything the commands of `t1ote_export_assets.py` share: reading
#  settings, the Tenable GraphQL client, asset columns and row shaping, and the Power BI
#  push-dataset client. It is intentionally small and dependency-light so it can be read
#  top to bottom, copied, and adapted.
#
#  ### Code map
#  - @ref config      : .env loading and validation
#  - @ref tenable     : GraphQL client for Tenable OT Exposure
#  - @ref scope       : filters, column selection and row shaping (pure functions)
#  - @ref powerbi     : Microsoft sign-in and the Power BI push-dataset REST API
#
#  @author Reference implementation, supplied as-is for evaluation.
#  @copyright Licensed under the Apache License, Version 2.0 (see LICENSE).
#  @version 0.2.0

from __future__ import annotations

import argparse
import configparser
import dataclasses
import difflib
import ipaddress
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

## @brief Program version, shown by `--version`.
__version__ = "0.2.0"

# ==========================================================================
# Constants
# ==========================================================================

## @brief Microsoft Entra ID (Azure AD) sign-in authority.
AUTHORITY = "https://login.microsoftonline.com"

## @brief Power BI REST API root. Workspace-scoped paths are appended to it.
POWERBI_API = "https://api.powerbi.com/v1.0/myorg"

## @brief OAuth scope requested at sign-in.
#  @details `Dataset.ReadWrite.All` lets us create datasets and write rows.
#  `offline_access` is what makes Entra return a *refresh token*, which is
#  what allows `assets --powerbi` to run unattended after the one-time `login`.
POWERBI_SCOPE = "https://analysis.windows.net/powerbi/api/Dataset.ReadWrite.All offline_access"

## @brief Assets requested per GraphQL page.
PAGE_SIZE = 500

## @brief Circuit breaker: stop paging after this many assets, in case the
#  server ever returns a cursor that never terminates.
SAFETY_MAX_ASSETS = 50_000

## @brief Power BI's hard cap on rows in a single "push rows" request.
PUSH_BATCH_ROWS = 10_000

## @brief Valid values for `--criticality-at-least`, lowest to highest.
CRITICALITY_LEVELS = ["none", "low", "medium", "high"]

## @brief Maps our friendly level names to Tenable's GraphQL enum values.
_CRITICALITY_ENUM = {
    "none": "NoneCriticality",
    "low": "LowCriticality",
    "medium": "MediumCriticality",
    "high": "HighCriticality",
}

## @brief Reverse map (lower-cased enum -> "Low", "High", ...) for display.
_CRITICALITY_DISPLAY = {v.lower(): k.capitalize() for k, v in _CRITICALITY_ENUM.items()}

## @brief Largest number of list items (IPs, tags, segments, ...) requested per asset.
LIST_FIRST = 50

## @brief Longest text written to one Power BI cell (longer values are cut and marked).
MAX_TEXT = 30_000

## @brief Fields that are very large; never part of `--export-all-columns`.
HEAVY_FIELDS = frozenset({"details", "layout"})

## @brief One column of the exported `assets` table.
#  @details `path` says where the value sits in an asset node returned by
#  Tenable (an empty path means the program supplies it: `site`, `exported_at`).
#  `join` says how a list is written into one cell: `"list"` joins the items with
#  `", "` (for a list of objects, the `sub[0]` field of each), `"json"` writes a JSON
#  array of objects with the fields in `sub`. `first` names a list field that needs a
#  page size, and `transform` is a named post-processing step.
@dataclasses.dataclass(frozen=True)
class Column:
    name: str
    path: tuple[str, ...]
    dtype: str = "string"
    join: str = ""
    transform: str = ""
    first: tuple[str, ...] = ()
    sub: tuple[str, ...] = ()
    gql: str = ""
    heavy: bool = False


## @brief Columns the program supplies itself (appended to every selection).
VIRTUAL_COLUMNS = [Column("site", ()), Column("exported_at", (), dtype="DateTime")]


def _list(name: str, field: str, sub: tuple[str, ...] = ()) -> Column:
    return Column(name, (field, "nodes"), join="list", first=(field,), sub=sub)


## @brief The Tenable OT *Inventory* view columns (the `AssetField` enum in the GraphQL schema).
#  @details `--export-all-columns` exports exactly these, minus any the server does not
#  know. Names are the Power BI column names.
INVENTORY_COLUMNS: list[Column] = [
    Column("asset_id", ("id",)),
    Column("name", ("name",)),
    Column("type", ("type",)),
    Column("super_type", ("superType",)),
    Column("category", ("category",)),
    Column("vendor", ("vendor",)),
    Column("family", ("family",)),
    Column("model", ("model",)),
    Column("os", ("os",)),
    Column("firmware_version", ("firmwareVersion",)),
    Column("serial", ("serial",)),
    Column("slot", ("slot",), dtype="Int64"),
    Column("criticality", ("criticality",), transform="criticality"),
    Column("total_risk", ("risk", "totalRisk"), dtype="Double"),
    Column("purdue_level", ("purdueLevel",)),
    Column("location", ("location",)),
    Column("description", ("description",)),
    _list("ips", "ips"),
    _list("macs", "macs"),
    _list("subnets", "subnets"),
    _list("segments", "segments", sub=("name",)),
    _list("segment_ids", "segments", sub=("id",)),
    _list("sources", "sources", sub=("name",)),
    _list("tags", "tags"),
    Column("backplane_id", ("backplane", "id")),
    Column("backplane_name", ("backplane", "name")),
    Column("run_status", ("runStatus",)),
    Column("extended_run_status", ("extendedRunStatus",)),
    Column("run_status_time", ("runStatusTime",)),
    Column("hardware_state", ("hardwareState",)),
    Column("lifecycle_status", ("lifecycleStatus",)),
    Column("discontinued_date", ("discontinuedDate",)),
    Column("replacement_product", ("replacementProduct",)),
    Column("hidden", ("hidden",), dtype="Boolean"),
    Column("first_seen", ("firstSeen",)),
    Column("last_seen", ("lastSeen",)),
    Column("last_hit", ("lastHit",)),
    Column("last_snapshot", ("lastSnapshot",)),
    Column("last_update", ("lastUpdate",)),
] + [Column(f"custom_field_{i}", (f"customField{i}",)) for i in range(1, 11)]

## @brief GraphQL type name of an asset node, used for introspection.
ASSET_TYPE = "Asset"

## @brief GraphQL: the fields of one type (introspection).
_QUERY_TYPE_FIELDS = """
query T($n: String!) {
  __type(name: $n) {
    fields { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
  }
}
"""

## @brief GraphQL: the user-defined names of the custom asset fields.
_QUERY_CUSTOM_FIELDS = """
query getCustomFields {
  customFields { fieldId userDefinedName valueType }
}
"""

## @brief GraphQL: list the sites (paired ICPs) known to the EM. Runs against
#  the EM *root* endpoint.
_QUERY_PAIRED_ICPS = """
query Q($pageSize: Int!) {
  emPairedIcps(first: $pageSize) {
    edges { node { site { machineId name } } }
  }
}
"""

## @brief GraphQL: one page of assets. Runs against a *site* endpoint.
#  @details `__SELECTION__` is replaced by `assets_query()`. `$filter` is optional; see `build_filter()` for its shape.
#  Pagination is cursor-based (`after` / `pageInfo.endCursor`).
_QUERY_ASSETS = """
query Q($pageSize: Int!, $after: String, $filter: AssetExpressionsParams) {
  assets(first: $pageSize, after: $after, filter: $filter) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes { __SELECTION__ }
  }
}
"""


## @brief The assets query with a caller-supplied node selection.
#  @param selection GraphQL field selection for one asset (see `build_selection()`).
def assets_query(selection: str) -> str:
    return _QUERY_ASSETS.replace("__SELECTION__", selection)


## @brief An error with a clear, user-facing message.
#  @details Everything the program *expects* can go wrong (bad config, a
#  rejected API key, an unreachable server) is raised as `ExportError`.
#  `main()` prints these as a one-line message with no traceback. Anything
#  that is *not* an `ExportError` is a genuine bug and gets a full traceback.
class ExportError(Exception):
    pass


## @brief Print a progress/diagnostic line to stderr.
#  @details Progress goes to stderr so that stdout carries only results
#  (handy for piping or scripting).
#  @param msg The text to print.
def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


## @brief Create an HTTP client. The *only* place clients are constructed.
#  @details Keeping construction in one function gives tests a single seam
#  to replace with a fake transport (see `tests/test_export.py`).
#  @param verify `True`/`False` to enable/disable TLS verification, or a
#         filesystem path to a CA bundle (PEM) to trust instead of the system store.
#  @param timeout Per-request timeout in seconds.
#  @return A configured `httpx.Client`.
def make_client(verify: bool | str = True, timeout: float = 30.0) -> httpx.Client:
    return httpx.Client(verify=verify, timeout=timeout)


# ==========================================================================
## @defgroup config Configuration
#  @brief Reading and validating settings from the environment / .env file.
#  @{


## @brief Read an environment variable, stripped of whitespace.
#  @param name Variable name.
#  @param default Value if unset.
#  @return The stripped value, or `default`.
def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


## @brief Fail with a helpful message if any named setting is missing/empty.
#  @param names One or more environment variable names that must be set.
#  @throws ExportError Listing every missing name at once (so the user can
#          fix them all in one pass rather than one error at a time).
def _require(*names: str) -> None:
    missing = [n for n in names if not _env(n)]
    if missing:
        raise ExportError(
            "Missing required setting(s) in your .env file: "
            + ", ".join(missing)
            + ". See .env.example."
        )


## @brief Valid values for the connection `mode` setting.
CONNECTION_MODES = ("auto", "em", "icp")


## @brief Short label for a URL: its host name (used to name a target in reports).
def _host_label(url: str) -> str:
    return urlparse(url).hostname or url


## @brief Settings for talking to one Tenable OT target: an Enterprise Manager or a standalone ICP.
@dataclass
class TenableConfig:
    ## Base URL, without a trailing slash.
    url: str
    ## Tenable OT API key: the single key string from the OT console, sent as `X-APIKeys: key=<value>`.
    api_key: str
    ## Optional Enterprise Manager site, by *name* (the id is looked up internally); empty = auto.
    site: str
    ## Whether to verify the server's TLS certificate.
    tls_verify: bool
    ## Optional path to a CA bundle to trust; wins over `tls_verify`.
    ca_bundle: str
    ## Name of this target: the config-file section, or the host name. Labels ICP data in reports.
    name: str = ""
    ## `auto` (detect EM or ICP), or force `em` / `icp`.
    mode: str = "auto"

    ## @brief Build from environment variables (the single-target case).
    #  @param url Overrides `TENABLE_URL` (from `--url`).
    #  @return A populated `TenableConfig`.
    #  @throws ExportError If a required setting is missing, the CA bundle path
    #          does not exist, or `TENABLE_MODE` is invalid.
    @classmethod
    def from_env(cls, url: str | None = None) -> TenableConfig:
        _require("TENABLE_API_KEY", *(() if url else ("TENABLE_URL",)))
        ca_bundle = _env("TENABLE_CA_BUNDLE")
        if ca_bundle and not Path(ca_bundle).is_file():
            raise ExportError(f"TENABLE_CA_BUNDLE points at {ca_bundle!r}, which is not a file.")
        mode = (_env("TENABLE_MODE") or "auto").lower()
        if mode not in CONNECTION_MODES:
            raise ExportError(f"TENABLE_MODE must be one of {', '.join(CONNECTION_MODES)}, not {mode!r}.")
        base = (url or _env("TENABLE_URL")).strip().rstrip("/")
        return cls(
            url=base,
            api_key=_env("TENABLE_API_KEY"),
            site=_env("TENABLE_SITE"),
            # Anything other than an explicit "off" value keeps verification ON.
            tls_verify=_env("TENABLE_TLS_VERIFY", "1").lower() not in ("0", "false", "no"),
            ca_bundle=ca_bundle,
            name=_host_label(base),
            mode=mode,
        )


## @brief Read a config file listing one or more Tenable targets.
#  @details INI format; every section is one target (a standalone ICP or an
#  Enterprise Manager) and the section name labels its data in reports:
#
#      [DEFAULT]                  ; optional, applies to every section
#      tls_verify = 0
#
#      [london]
#      url = https://london.example.com
#      api_key = ...              ; or: api_key_env = LONDON_KEY
#      [sydney]
#      url = https://sydney.example.com
#      api_key_env = SYDNEY_KEY
#      [corp-em]
#      url = https://em.example.com
#      api_key_env = EM_KEY
#      site = Head Office         ; optional, Enterprise Manager only
#
#  Recognised keys: `url`, `api_key` or `api_key_env`, `site`, `ca_bundle`
#  (relative paths resolve against the file's folder), `tls_verify`, `mode`.
#  @param path The config file.
#  @return One `TenableConfig` per section, in file order.
#  @throws ExportError If the file is unreadable, empty, or a section is incomplete.
def load_config_file(path: str) -> list[TenableConfig]:
    cfg_path = Path(path).expanduser()
    if not cfg_path.is_file():
        raise ExportError(f"Config file {path!r} not found.")
    cp = configparser.ConfigParser(interpolation=None)  # keys may legitimately contain '%'
    try:
        cp.read(cfg_path, encoding="utf-8")
    except configparser.Error as e:
        raise ExportError(f"Config file {path!r} could not be parsed: {e}") from e
    try:
        if cfg_path.stat().st_mode & 0o077 and os.name == "posix":
            log(f"Warning: {path} is readable by other users and may hold API keys; run: chmod 600 {path}")
    except OSError:
        pass
    if not cp.sections():
        raise ExportError(f"Config file {path!r} has no [target] sections.")
    out: list[TenableConfig] = []
    for sec in cp.sections():
        g = lambda key, default="": cp.get(sec, key, fallback=default).strip()  # noqa: E731
        url = g("url").rstrip("/")
        if not url:
            raise ExportError(f"Config file {path!r}, [{sec}]: 'url' is required.")
        key = g("api_key")
        env_name = g("api_key_env")
        if not key and env_name:
            key = os.environ.get(env_name, "").strip()
            if not key:
                raise ExportError(f"Config file {path!r}, [{sec}]: environment variable {env_name} (api_key_env) is not set.")
        if not key:
            raise ExportError(f"Config file {path!r}, [{sec}]: set 'api_key' or 'api_key_env'.")
        ca = g("ca_bundle")
        if ca:
            ca_path = Path(ca).expanduser()
            if not ca_path.is_absolute():
                ca_path = cfg_path.parent / ca_path
            if not ca_path.is_file():
                raise ExportError(f"Config file {path!r}, [{sec}]: ca_bundle {str(ca_path)!r} is not a file.")
            ca = str(ca_path)
        mode = g("mode", "auto").lower()
        if mode not in CONNECTION_MODES:
            raise ExportError(f"Config file {path!r}, [{sec}]: mode must be one of {', '.join(CONNECTION_MODES)}.")
        out.append(
            TenableConfig(
                url=url,
                api_key=key,
                site=g("site"),
                tls_verify=g("tls_verify", "1").lower() not in ("0", "false", "no"),
                ca_bundle=ca,
                name=sec,
                mode=mode,
            )
        )
    return out


## @brief Add the connection options shared by every command that talks to Tenable.
#  @details There is deliberately no `--api-key`: a key on the command line ends
#  up in shell history and the process list. Use the environment, `.env`, or a config file.
def add_connection_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("connection")
    g.add_argument("--config", metavar="FILE", help="INI file listing one or more Tenable targets (each section is an ICP or EM); see README.")
    g.add_argument("--target", action="append", metavar="NAME", help="With --config: use only this section (repeatable). Default: all sections.")
    g.add_argument("--url", help="Tenable base URL (overrides TENABLE_URL; not with --config).")
    g.add_argument("--site", metavar="NAME", help="Enterprise Manager only: the site to use, by name; 'all' for every paired site. Ignored for a standalone ICP.")
    g.add_argument("--mode", choices=CONNECTION_MODES, help="Force 'em' or 'icp' instead of detecting it (default: auto).")


## @brief Work out the Tenable target(s) from the command line, config file and environment.
#  @param args Parsed arguments (from `add_connection_args`).
#  @return One or more `TenableConfig`s.
#  @throws ExportError On conflicting options or incomplete settings.
def load_targets(args: argparse.Namespace) -> list[TenableConfig]:
    if args.config:
        if args.url:
            raise ExportError("--url cannot be combined with --config; put the URL in the config file.")
        targets = load_config_file(args.config)
        if args.target:
            wanted = {t.lower() for t in args.target}
            known = {t.name.lower(): t.name for t in targets}
            unknown = sorted(wanted - set(known))
            if unknown:
                raise ExportError(f"No target named {', '.join(unknown)} in {args.config}. Available: {', '.join(t.name for t in targets)}.")
            targets = [t for t in targets if t.name.lower() in wanted]
    else:
        if args.target:
            raise ExportError("--target needs --config.")
        targets = [TenableConfig.from_env(url=args.url)]
    if args.site:
        targets = [dataclasses.replace(t, site=args.site.strip()) for t in targets]
    if args.mode:
        targets = [dataclasses.replace(t, mode=args.mode) for t in targets]
    return targets


## @brief Settings for Microsoft sign-in and the Power BI destination.
@dataclass
class PowerBIConfig:
    ## Entra directory (tenant) ID.
    tenant_id: str
    ## Entra application (client) ID of the customer's app registration.
    client_id: str
    ## Power BI workspace (group) GUID; empty string means "My workspace".
    workspace_id: str
    ## GUID of the push dataset (set after `create-dataset`).
    dataset_id: str
    ## Display name used when creating the dataset.
    dataset_name: str
    ## Table inside the dataset that receives the assets.
    table_name: str
    ## File holding the sign-in refresh token (a credential).
    token_cache: Path

    ## @brief Build from environment variables.
    #  @param need_dataset True for commands that write rows (`assets --powerbi`), which
    #         additionally require `POWERBI_DATASET_ID`. `login` and
    #         `create-dataset` run *before* that ID exists, so they pass False.
    #  @return A populated `PowerBIConfig`.
    #  @throws ExportError If a required setting is missing.
    @classmethod
    def from_env(cls, *, need_dataset: bool) -> PowerBIConfig:
        _require("AZURE_TENANT_ID", "AZURE_CLIENT_ID")
        if need_dataset:
            _require("POWERBI_DATASET_ID")
        return cls(
            tenant_id=_env("AZURE_TENANT_ID"),
            client_id=_env("AZURE_CLIENT_ID"),
            workspace_id=_env("POWERBI_WORKSPACE_ID"),
            dataset_id=_env("POWERBI_DATASET_ID"),
            dataset_name=_env("POWERBI_DATASET_NAME") or "Tenable OT Asset Export",
            table_name=_env("POWERBI_TABLE_NAME") or "assets",
            token_cache=Path(_env("TOKEN_CACHE_FILE") or ".powerbi_token.json").expanduser(),
        )


## @}


# ==========================================================================
## @defgroup tenable Tenable One OT Exposure client
#  @brief A minimal GraphQL client for Tenable OT Exposure / Enterprise Manager.
#  @{


## @brief GraphQL client for Tenable One OT Exposure / Enterprise Manager.
#  @details Tenable's data is split across two kinds of endpoint:
#  - the **EM root**, `<url>/graphql`, knows which sites exist;
#  - each **site** (a paired ICP) serves its own assets at
#    `<url>/<site machine id>/graphql`.
#
#  Asset queries must therefore be sent to a *site* endpoint. Sending one to
#  the EM root fails. `query()` picks the endpoint from its `site_id` argument.
class Tenable:
    ## @brief Create a client.
    #  @param cfg Connection settings (see `TenableConfig`).
    def __init__(self, cfg: TenableConfig) -> None:
        self.cfg = cfg
        # A configured CA bundle path always wins over the on/off flag.
        verify: bool | str = cfg.ca_bundle if cfg.ca_bundle else cfg.tls_verify
        self._http = make_client(verify=verify)
        self._mode: str | None = None
        self._sites_cache: list[dict[str, str]] | None = None

    ## @brief Run one GraphQL operation and return its `data` payload.
    #  @param query The GraphQL document.
    #  @param variables GraphQL variables for the document.
    #  @param site_id Site machine id to target a site endpoint; `None` targets
    #         the EM root.
    #  @return The `data` object of the GraphQL response (empty dict if none).
    #  @throws ExportError On transport failure, HTTP 4xx/5xx, a non-JSON body
    #          (usually a wrong URL or site id), or a GraphQL `errors` array.
    def query(self, query: str, variables: dict[str, Any], site_id: str | None = None) -> dict[str, Any]:
        endpoint = f"{self.cfg.url}/{site_id}/graphql" if site_id else f"{self.cfg.url}/graphql"
        headers = {
            "X-APIKeys": f"key={self.cfg.api_key}",  # Tenable's API-key header format
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            resp = self._http.post(endpoint, headers=headers, json={"query": query, "variables": variables})
        except httpx.HTTPError as e:
            raise ExportError(f"Could not reach Tenable at {endpoint}: {e}") from e

        # Check status codes from most to least specific so the message is actionable.
        if resp.status_code in (401, 403):
            raise ExportError(
                f"Tenable rejected the API key (HTTP {resp.status_code}). Check TENABLE_API_KEY "
                "(the single API key from the OT console) and that the key's user may read assets."
            )
        if resp.status_code >= 400:
            raise ExportError(f"Tenable returned HTTP {resp.status_code} from {endpoint}: {resp.text[:300]}")
        try:
            body = resp.json()
        except json.JSONDecodeError as e:
            # A well-formed request that hits the wrong place (a web UI, a load
            # balancer, or a site id that is not paired) typically answers with HTML.
            raise ExportError(
                f"Tenable returned a non-JSON response from {endpoint} "
                f"(first bytes: {' '.join(resp.text[:150].split())!r}). Check TENABLE_URL points at the "
                "GraphQL-serving host/port, and that the site id is a currently paired site."
            ) from e
        # GraphQL reports query errors with HTTP 200 and an `errors` array.
        if isinstance(body, dict) and body.get("errors"):
            raise ExportError(
                "Tenable GraphQL error: " + "; ".join(e.get("message", str(e)) for e in body["errors"])
            )
        return body.get("data") or {}

    ## @brief List the sites (paired ICPs) on the EM.
    #  @return A list of `{"name": ..., "machine_id": ...}` dicts (possibly empty).
    def paired_sites(self) -> list[dict[str, str]]:
        data = self.query(_QUERY_PAIRED_ICPS, {"pageSize": 500})
        sites = []
        for edge in (data.get("emPairedIcps") or {}).get("edges") or []:
            # Be defensive: skip any edge missing a usable id or name.
            site = ((edge or {}).get("node") or {}).get("site") or {}
            mid, name = site.get("machineId"), site.get("name")
            if isinstance(mid, str) and isinstance(name, str) and mid.strip() and name.strip():
                sites.append({"name": name.strip(), "machine_id": mid.strip("/")})
        return sites

    ## @brief Decide whether this target is an Enterprise Manager or a standalone ICP.
    #  @details Order of checks: a forced `mode` setting; then the `isEm` GraphQL
    #  field; then, if the server does not know that field, a probe of the EM-only
    #  `emPairedIcps` query (success means EM, a GraphQL error means ICP).
    #  Transport and authentication failures are *never* read as "ICP": they propagate.
    #  @return `"em"` or `"icp"`.
    #  @throws ExportError On connection or authentication failure.
    def detect_mode(self) -> str:
        if self.cfg.mode in ("em", "icp"):
            return self.cfg.mode
        if self._mode:
            return self._mode
        try:
            # Schema: `isEm: isEmMachine!` where `type isEmMachine { isEm: Boolean! }`.
            node = self.query("query { isEm { isEm } }", {}).get("isEm")
            v = node.get("isEm") if isinstance(node, dict) else None
            if isinstance(v, bool):
                self._mode = "em" if v else "icp"
                log(f"{self.cfg.name or self.cfg.url}: {'Enterprise Manager' if v else 'standalone ICP'} (isEm)")
                return self._mode
        except ExportError as e:
            if "GraphQL error" not in str(e):
                raise
        try:
            self._sites_cache = self.paired_sites()
            self._mode = "em"
        except ExportError as e:
            if "GraphQL error" not in str(e):
                raise
            self._mode = "icp"
        log(f"{self.cfg.name or self.cfg.url}: {'Enterprise Manager' if self._mode == 'em' else 'standalone ICP'} (detected by probe)")
        return self._mode

    ## @brief Decide which sites to read from this target.
    #  @details A standalone ICP has no sites: there is one pseudo-site, queried at
    #  the root endpoint and labelled with the target's name. On an Enterprise
    #  Manager the `site` setting (a site *name*; the id is looked up here) picks
    #  one site, `all` picks every paired site, and with neither a single paired
    #  site is used automatically.
    #  @return A list of `(site_machine_id | None, label)`; the id is `None` for an ICP.
    #  @throws ExportError If nothing is paired, the name is unknown, or several
    #          sites exist and none was chosen.
    def sites_to_scan(self) -> list[tuple[str | None, str]]:
        if self.detect_mode() == "icp":
            return [(None, self.cfg.name or _host_label(self.cfg.url))]
        sites = self._sites_cache if self._sites_cache is not None else self.paired_sites()
        self._sites_cache = sites
        if not sites:
            raise ExportError("No paired sites found on this Enterprise Manager; at least one ICP must be paired.")
        want = self.cfg.site.strip()
        names = ", ".join(sorted(s["name"] for s in sites))
        if want:
            for s in sites:
                if s["name"].lower() == want.lower():
                    return [(s["machine_id"], s["name"])]
            if want.lower() == "all":
                return [(s["machine_id"], s["name"]) for s in sites]
            raise ExportError(f"No site named {want!r}. Available: {names}.")
        if len(sites) == 1:
            return [(sites[0]["machine_id"], sites[0]["name"])]
        raise ExportError(f"Multiple sites are paired ({names}). Pass --site NAME, or --site all.")

    ## @brief Ask the server which fields a GraphQL type has (introspection).
    #  @param type_name GraphQL type name, e.g. `"Asset"`.
    #  @param site_id Site endpoint to ask, or `None` for the root endpoint.
    #  @return `{field name: (leaf type name, is_list)}`, or `None` if the server
    #          has no such type or does not allow introspection.
    #  @throws ExportError On connection or authentication failure.
    def type_fields(self, type_name: str, site_id: str | None = None) -> dict[str, tuple[str, bool]] | None:
        try:
            data = self.query(_QUERY_TYPE_FIELDS, {"n": type_name}, site_id=site_id)
        except ExportError as e:
            if "GraphQL error" not in str(e):
                raise
            return None
        fields = (data.get("__type") or {}).get("fields")
        if not isinstance(fields, list):
            return None
        out: dict[str, tuple[str, bool]] = {}
        for f in fields:
            t, is_list = (f or {}).get("type"), False
            while isinstance(t, dict) and not t.get("name"):  # unwrap NON_NULL / LIST wrappers
                is_list = is_list or t.get("kind") == "LIST"
                t = t.get("ofType")
            if isinstance(f.get("name"), str) and isinstance(t, dict):
                out[f["name"]] = (str(t.get("name")), is_list or t.get("kind") == "LIST")
        return out

    ## @brief The names given to the custom asset fields in the OT console.
    #  @param site_id Site machine id, or `None` for a standalone ICP.
    #  @return `{n: name}` for custom field `n` (asset field `customField<n>`); unnamed
    #          fields are left out. `None` if the server cannot say.
    #  @throws ExportError On connection or authentication failure.
    def custom_fields(self, site_id: str | None = None) -> dict[int, str] | None:
        try:
            data = self.query(_QUERY_CUSTOM_FIELDS, {}, site_id=site_id)
        except ExportError as e:
            if "GraphQL error" not in str(e):
                raise
            return None
        out: dict[int, str] = {}
        for f in data.get("customFields") or []:
            m = re.search(r"(\d+)\s*$", str((f or {}).get("fieldId", "")))
            name = (f or {}).get("userDefinedName")
            if m and isinstance(name, str) and name.strip():
                out[int(m.group(1))] = name.strip()
        return out

    ## @brief The fields the server's asset type offers (`None` if it cannot say).
    #  @param site_id Site machine id, or `None` for a standalone ICP.
    def asset_fields(self, site_id: str | None = None) -> dict[str, tuple[str, bool]] | None:
        return self.type_fields(ASSET_TYPE, site_id)

    ## @brief Page through a site's assets.
    #  @details Requests `PAGE_SIZE` assets at a time, following the GraphQL
    #  cursor until `hasNextPage` is false, `limit` is reached, or the
    #  `SAFETY_MAX_ASSETS` breaker trips. Progress is logged to stderr.
    #  @param site_id Site machine id (see `sites_to_scan()`).
    #  @param filt Filter from `build_filter()`, or `None` for every asset.
    #  @param limit Maximum number of assets to return, or `None` for all.
    #  @param columns Columns to request (from `resolve_columns()`).
    #  @return `(total_count, nodes)`: Tenable's reported match count (which can
    #          exceed `len(nodes)` when `limit` is used) and the asset dicts.
    #  @throws ExportError Propagated from `query()`.
    def fetch_assets(self, site_id: str | None, filt: dict | None, limit: int | None, columns: list[Column]) -> tuple[int, list[dict[str, Any]]]:
        query = assets_query(build_selection(columns))
        nodes: list[dict[str, Any]] = []
        total = 0
        cursor: str | None = None
        while limit is None or len(nodes) < limit:
            # Never over-fetch past the requested limit.
            size = PAGE_SIZE if limit is None else min(PAGE_SIZE, limit - len(nodes))
            variables: dict[str, Any] = {"pageSize": size}
            if cursor:
                variables["after"] = cursor
            if filt is not None:
                variables["filter"] = filt
            conn = self.query(query, variables, site_id=site_id).get("assets") or {}
            total = conn.get("totalCount") or 0
            page = conn.get("nodes") or []
            nodes.extend(page)
            log(f"  fetched {len(nodes)} / {total if limit is None else min(total, limit)}")
            info = conn.get("pageInfo") or {}
            cursor = info.get("endCursor")
            # Stop on: no more pages, an empty page, or a missing cursor.
            if not info.get("hasNextPage") or not page or not cursor:
                break
            if len(nodes) >= SAFETY_MAX_ASSETS:
                log(f"  stopping at the {SAFETY_MAX_ASSETS}-asset safety limit")
                break
        return total, (nodes if limit is None else nodes[:limit])


## @}


# ==========================================================================
## @defgroup scope Scope and row shaping
#  @brief Pure functions (no network, no I/O) that turn command-line scope into
#         a Tenable filter, and Tenable assets into Power BI rows. Easy to unit test.
#  @{


## @brief Parse an `--ip-range` value such as `10.0.0.10-10.0.0.99`.
#  @param text The raw argument.
#  @return `(start, end)` as normalised address strings.
#  @throws ExportError If the format is wrong, an address is invalid, the IP
#          versions differ, or start is greater than end.
def parse_ip_range(text: str) -> tuple[str, str]:
    parts = [p.strip() for p in text.split("-")]
    if len(parts) != 2 or not all(parts):
        raise ExportError(f"--ip-range must look like START-END (e.g. 10.0.0.10-10.0.0.99), got {text!r}")
    try:
        a, b = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
    except ValueError as e:
        raise ExportError(f"--ip-range has an invalid address: {e}") from e
    if a.version != b.version or a > b:
        raise ExportError(f"--ip-range {text!r}: start must be <= end and both the same IP version.")
    return str(a), str(b)


## @brief Build the Tenable GraphQL `filter` for the chosen scope.
#  @details Each option contributes one clause; several are combined with AND.
#  - criticality: an `In` clause listing the chosen level *and every level above it*.
#  - subnet / IP range: a `Between` clause on the asset's `ips` field, using the
#    first and last address of the range.
#
#  Example result for `--subnet 10.1.0.0/24 --criticality-at-least high`:
#  @code{.json}
#  {"op": "And", "expressions": [
#     {"field": "criticality", "op": "In", "values": ["HighCriticality"]},
#     {"field": "ips", "op": "Between", "values": ["10.1.0.0", "10.1.0.255"]}]}
#  @endcode
#  @param criticality_at_least One of `CRITICALITY_LEVELS`, or `None`.
#  @param subnet A CIDR such as `10.253.10.128/25`, or `None`.
#  @param ip_range A `START-END` range, or `None`. Mutually exclusive with `subnet`.
#  @return The filter dict, or `None` when no scope option was given (export everything).
#  @throws ExportError On invalid values or when both `subnet` and `ip_range` are given.
def build_filter(
    criticality_at_least: str | None, subnet: str | None, ip_range: str | None
) -> dict | None:
    parts: list[dict] = []
    if criticality_at_least:
        if criticality_at_least not in CRITICALITY_LEVELS:
            raise ExportError(f"--criticality-at-least must be one of {CRITICALITY_LEVELS}")
        idx = CRITICALITY_LEVELS.index(criticality_at_least)
        parts.append(
            {
                "field": "criticality",
                "op": "In",
                "values": [_CRITICALITY_ENUM[lv] for lv in CRITICALITY_LEVELS[idx:]],
            }
        )
    if subnet and ip_range:
        raise ExportError("Use --subnet or --ip-range, not both.")
    if subnet:
        try:
            # strict=False lets users pass a host address with a mask (10.1.2.3/24).
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            raise ExportError(f"--subnet {subnet!r} is not a valid CIDR: {e}") from e
        parts.append(
            {"field": "ips", "op": "Between", "values": [str(net.network_address), str(net.broadcast_address)]}
        )
    if ip_range:
        start, end = parse_ip_range(ip_range)
        parts.append({"field": "ips", "op": "Between", "values": [start, end]})
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else {"op": "And", "expressions": parts}


## @brief Lower-case a column token and drop punctuation, so `last_seen`, `lastSeen` and `Last Seen` match.
def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


## @brief `camelCase` -> `snake_case` (used for columns discovered from the server's schema).
def _snake(text: str) -> str:
    return re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", text).lower()


## @brief Extra spellings accepted for a column, mapped to its name.
_ALIASES = {
    "id": "asset_id", "risk": "total_risk", "firmware": "firmware_version", "purdue": "purdue_level",
    "ip": "ips", "mac": "macs", "subnet": "subnets", "tag": "tags", "segment": "segments",
    "source": "sources",
}

## @brief GraphQL scalar types written as Power BI text.
_TEXT_SCALARS = ("String", "ID", "Time", "DateTime")

## @brief GraphQL scalar types written as a Power BI number (everything else is text).
_PBI_TYPES = {"Int": "Int64", "Long": "Int64", "Float": "Double", "Boolean": "Boolean"}


## @brief The GraphQL node selection that fetches the given columns.
#  @details Builds a tree from each column's `path` (a list field gets `(first: LIST_FIRST)`
#  and a list of objects gets its `sub` fields), so two columns sharing a field
#  (`segments`, `segment_ids`) produce one query field.
#  @param columns Columns from `resolve_columns()`.
#  @return A selection for `assets_query()`. `id` is always included.
def build_selection(columns: list[Column]) -> str:
    tree: dict[str, Any] = {"id": {}}
    for c in columns:
        node = tree
        for key in c.path:
            node = node.setdefault(f"{key}(first: {LIST_FIRST})" if key in c.first else key, {})
        for f in c.sub:
            node.setdefault(f, {})

    def render(t: dict[str, Any]) -> str:
        return " ".join(k + (" { " + render(v) + " }" if v else "") for k, v in t.items())

    return render(tree)


## @brief Work out which columns were asked for, from the command line and `.env`.
#  @details Precedence: `--export-all-columns` / `--export-columns` (not both), then the
#  `TENABLE_EXPORT_COLUMNS` setting (a comma-separated list, or `all`), then the default.
#  @param args Parsed arguments (from `add_column_args`).
#  @return `"all"` (the default) or a list of column names.
#  @throws ExportError If both options are given.
def columns_spec(args: argparse.Namespace) -> str | list[str]:
    if args.export_all_columns and args.export_columns:
        raise ExportError("Use either --export-all-columns or --export-columns, not both.")
    if args.export_all_columns:
        return "all"
    text = args.export_columns if args.export_columns is not None else _env("TENABLE_EXPORT_COLUMNS")
    names = [t.strip() for t in re.split(r"[,\n]+", re.sub(r"[\[\]\"']", "", text or "")) if t.strip()]
    if not names:
        return "all"
    return "all" if [n.lower() for n in names] == ["all"] else names


## @brief Add the column-selection options.
def add_column_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("columns (default: every Tenable OT Inventory-view column)")
    g.add_argument("--export-all-columns", action="store_true", help="Export every Inventory-view column (this is the default; see the `columns` command).")
    g.add_argument("--export-columns", metavar="LIST", help="Limit the export to these comma-separated columns, e.g. name,vendor,ips,last_seen (or set TENABLE_EXPORT_COLUMNS). asset_id, site and exported_at are always included.")


## @brief Add the scope options (which assets to include).
def add_scope_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("scope (default: every asset)")
    g.add_argument("--subnet", help="Only assets with an IP in this CIDR, e.g. 10.253.10.128/25.")
    g.add_argument("--ip-range", help="Only assets with an IP in this range, e.g. 10.0.0.10-10.0.0.99.")
    g.add_argument("--criticality-at-least", choices=CRITICALITY_LEVELS, help="Minimum asset criticality.")
    g.add_argument("--limit", type=int, help="At most this many assets per site.")


## @brief Add the output options shared by the commands that produce results.
def add_output_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("output")
    g.add_argument("--out-dir", default="t1ote_out", help="Where CSV/JSON files are written (default ./t1ote_out).")
    g.add_argument("--powerbi", action="store_true", help="Also replace the Power BI table(s) with these results (needs `create-dataset`; see README).")
    g.add_argument("--dry-run", action="store_true", help="Fetch and summarise only; write no files and touch no Power BI.")


## @brief The custom-field columns, named after the console's field names.
#  @details `customField<n>` exists for each n the server's asset type has (so more than
#  10 works when Tenable adds them; with no schema, 1-10 are assumed). A field named
#  "Cost Centre" becomes the column `Cost Centre` (spaces and case are kept; Power BI allows
#  both). An unnamed field, or a name that clashes with another column, stays
#  `custom_field_<n>`. Any spelling is accepted when selecting (`cost_centre`, `Cost Centre`).
#  @param fields From `Tenable.asset_fields()` (or `None`).
#  @param names From `Tenable.custom_fields()` (or `None`).
def custom_columns(fields: dict[str, tuple[str, bool]] | None, names: dict[int, str] | None) -> list[Column]:
    if fields is None:
        nums = list(range(1, 11))
    else:
        nums = sorted(int(m.group(1)) for f in fields if (m := re.fullmatch(r"customField(\d+)", f)))
    taken = {c.name.lower() for c in INVENTORY_COLUMNS if not c.name.startswith("custom_field_")} | {"site", "exported_at"}
    out: list[Column] = []
    for n in nums:
        label = " ".join((names or {}).get(n, "").split())
        if not label or label.lower() in taken:       # Power BI column names are case-insensitive
            label = f"custom_field_{n}"
        taken.add(label.lower())
        out.append(Column(label, (f"customField{n}",)))
    return out


## @brief The inventory catalogue with the custom fields named as in the console.
def catalogue(fields: dict[str, tuple[str, bool]] | None = None, names: dict[int, str] | None = None) -> list[Column]:
    return [c for c in INVENTORY_COLUMNS if not c.name.startswith("custom_field_")] + custom_columns(fields, names)


## @brief Scalar fields the server's asset type has that the inventory catalogue lacks.
#  @param fields From `Tenable.asset_fields()` (or `None`).
#  @return `{GraphQL field name: Column}`; only for fields named explicitly, never in `all`.
def extra_columns(fields: dict[str, tuple[str, bool]] | None) -> dict[str, Column]:
    listed = {c.path[0] for c in INVENTORY_COLUMNS if c.path}
    out: dict[str, Column] = {}
    for fname, (tname, is_list) in (fields or {}).items():
        if fname in listed or re.fullmatch(r"customField\d+", fname) or fname in HEAVY_FIELDS or fname.startswith("__") or is_list:
            continue
        if tname in _PBI_TYPES or tname in _TEXT_SCALARS:
            out[fname] = Column(_snake(fname), (fname,), dtype=_PBI_TYPES.get(tname, "string"))
    return out


## @brief Turn a column request into the list of `Column`s to export.
#  @param spec From `columns_spec()`: `"all"` or a list of names.
#  @param fields The server's asset fields (`Tenable.asset_fields()`), or `None` if unknown.
#         With it, `all` skips inventory columns this Tenable version lacks, and a
#         named column the server lacks is an error; scalar fields outside the
#         inventory catalogue can be named too.
#  @param custom_names Custom field names from `Tenable.custom_fields()`, if known.
#  @return Columns in export order: `asset_id`, `site`, the rest, `exported_at`.
#  @throws ExportError For an unknown name (with suggestions) or one this server lacks.
def resolve_columns(
    spec: str | list[str],
    fields: dict[str, tuple[str, bool]] | None = None,
    custom_names: dict[int, str] | None = None,
) -> list[Column]:
    def known(c: Column) -> bool:
        return fields is None or not c.path or c.path[0] in fields

    cat = catalogue(fields, custom_names)
    index: dict[str, Column] = {}
    for c in cat + VIRTUAL_COLUMNS:
        index.setdefault(_norm(c.name), c)
        if c.path and (len(c.path) == 1 or c.join == "list"):
            index.setdefault(_norm(c.path[0]), c)
    for c in cat:
        if re.fullmatch(r"customField\d+", c.path[0] if c.path else ""):
            index.setdefault(_norm(c.path[0]), c)       # customField3 / custom_field_3 always work
    for alias, target in _ALIASES.items():
        index.setdefault(alias, index[_norm(target)])
    for fname, col in extra_columns(fields).items():
        index.setdefault(_norm(fname), col)

    if spec == "all":
        chosen = [c for c in cat if known(c)]
        skipped = [c.name for c in cat if not known(c)]
        if skipped:
            log(f"Skipping inventory column(s) this Tenable version does not have: {', '.join(skipped)}")
    else:
        chosen = []
        for token in spec:
            col = index.get(_norm(token))
            if col is None:
                if _norm(token) in {_norm(h) for h in HEAVY_FIELDS}:
                    raise ExportError(f"{token!r} is a large nested structure and cannot be exported as a column.")
                hint = difflib.get_close_matches(_norm(token), list(index), n=3, cutoff=0.6)
                more = f" Did you mean: {', '.join(sorted({index[h].name for h in hint}))}?" if hint else ""
                raise ExportError(f"Unknown column {token!r}.{more} Run the `columns` command to list the available columns.")
            if not known(col):
                raise ExportError(f"Column {col.name!r} (Tenable field {col.path[0]!r}) is not available on this Tenable version.")
            chosen.append(col)

    by_name: dict[str, Column] = {c.name: c for c in chosen}
    first = [index["assetid"], index["site"]]
    last = [index["exportedat"]]
    rest = [c for c in by_name.values() if c not in first + last]
    out: list[Column] = []
    for c in first + rest + last:
        if c.name not in {o.name for o in out}:
            out.append(c)
    return out


## @brief Resolve the column options for a command that creates a dataset or exports.
#  @details Asks the first target's first site which asset fields and custom-field names
#  exist (see `resolve_columns()`), so it needs the Tenable connection settings.
#  @param args Parsed arguments (connection and column options).
#  @param clients Already-created `Tenable` clients to reuse, or `None` to create them.
#  @return The columns to export.
def resolve_selected_columns(args: argparse.Namespace, clients: list[Tenable] | None = None) -> list[Column]:
    spec = columns_spec(args)
    tenable = (clients or [Tenable(cfg) for cfg in load_targets(args)])[0]
    site_id = tenable.sites_to_scan()[0][0]
    return resolve_columns(spec, tenable.asset_fields(site_id), tenable.custom_fields(site_id))


## @brief Render one cell, converting to the column's Power BI type.
def _cell(col: Column, node: dict[str, Any], site_label: str, exported_at: str) -> Any:
    if col.name == "site":
        return site_label
    if col.name == "exported_at":
        return exported_at
    v: Any = node
    for key in col.path:
        v = v.get(key) if isinstance(v, dict) else None
    if col.join and isinstance(v, list):
        if col.join == "json":
            v = json.dumps([{f: i.get(f) for f in col.sub} if isinstance(i, dict) else i for i in v])
        else:
            items = [i.get(col.sub[0]) if col.sub and isinstance(i, dict) else i for i in v]
            v = ", ".join(str(i) for i in items if i is not None)
    if col.transform == "criticality":
        raw = v if isinstance(v, str) else ""
        return _CRITICALITY_DISPLAY.get(raw.lower(), raw)
    if col.dtype == "Int64":
        return v if isinstance(v, int) and not isinstance(v, bool) else None
    if col.dtype == "Double":
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None
    if col.dtype == "Boolean":
        return v if isinstance(v, bool) else None
    if v is None:
        return ""
    text = v if isinstance(v, str) else json.dumps(v) if isinstance(v, (dict, list)) else str(v)
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 12] + " [truncated]"


## @brief Turn Tenable asset nodes into flat Power BI rows.
#  @param nodes Asset dicts as returned by `Tenable.fetch_assets()`.
#  @param site_label Site display name written to every row's `site` column
#         (assets are queried per site and carry no site field themselves).
#  @param columns Columns to write (from `resolve_columns()`).
#  @return A list of row dicts, one per asset, in the same order.
def build_rows(nodes: list[dict[str, Any]], site_label: str, columns: list[Column]) -> list[dict[str, Any]]:
    exported_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return [{c.name: _cell(c, n, site_label, exported_at) for c in columns} for n in nodes]


## @}


# ==========================================================================
## @defgroup powerbi Power BI
#  @brief Microsoft sign-in (device code flow) and the Power BI push-dataset REST API.
#
#  @details Why a *push dataset* and a *user* sign-in? Push datasets accept rows
#  directly over REST with no refresh step, and they work on a Power BI Pro
#  licence. Microsoft does not allow service principals (app-only auth) to
#  write to push datasets, so a real user signs in once (`login`) and the
#  program keeps working from the stored refresh token afterwards.
#  @{


## @brief Turn an Entra error response into a short readable string.
#  @param resp The failed HTTP response.
#  @return `"<error>: <description>"`, falling back to status and body text.
def _aad_error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        return f"{body.get('error', resp.status_code)}: {body.get('error_description', '')[:300]}"
    except Exception:
        return f"HTTP {resp.status_code}: {resp.text[:300]}"


## @brief Persist the refresh token, readable only by the current user.
#  @details Written to a temp file then atomically renamed, so a crash
#  mid-write can never leave a truncated (unusable) token file behind.
#  @param path Destination file (the `TOKEN_CACHE_FILE` setting).
#  @param refresh_token The token to store.
def _save_refresh_token(path: Path, refresh_token: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps({"refresh_token": refresh_token}))
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0600: it is a credential
    os.replace(tmp, path)


## @brief Interactive one-time Microsoft sign-in using the device code flow.
#  @details Prints a short code and a URL. The user opens the URL in *any*
#  browser, enters the code and signs in; meanwhile this function polls the
#  token endpoint until sign-in completes, then stores the refresh token.
#  The device-code flow suits CLI tools: no local web server or redirect URI.
#  @param cfg Power BI / Entra settings.
#  @throws ExportError If Microsoft rejects the request, the user declines, or
#          the code expires (15 minutes by default).
def device_login(cfg: PowerBIConfig) -> None:
    http = make_client()
    base = f"{AUTHORITY}/{cfg.tenant_id}/oauth2/v2.0"
    # Step 1: ask Microsoft for a device code + user code.
    try:
        r = http.post(f"{base}/devicecode", data={"client_id": cfg.client_id, "scope": POWERBI_SCOPE})
    except httpx.HTTPError as e:
        raise ExportError(f"Could not reach Microsoft sign-in: {e}") from e
    if r.status_code >= 400:
        raise ExportError(
            f"Microsoft rejected the sign-in request ({_aad_error(r)}). Check AZURE_TENANT_ID / "
            "AZURE_CLIENT_ID, and that 'Allow public client flows' is enabled on the app registration."
        )
    dc = r.json()
    print(dc.get("message") or f"Open {dc['verification_uri']} and enter code {dc['user_code']}")

    # Step 2: poll until the user finishes signing in.
    interval = float(dc.get("interval", 5))
    deadline = time.monotonic() + float(dc.get("expires_in", 900))
    while time.monotonic() < deadline:
        time.sleep(interval)
        t = http.post(
            f"{base}/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": cfg.client_id,
                "device_code": dc["device_code"],
            },
        )
        if t.status_code == 200:
            _save_refresh_token(cfg.token_cache, t.json()["refresh_token"])
            print(f"Signed in. Token saved to {cfg.token_cache}")
            return
        err = (t.json() if t.content else {}).get("error", "")
        if err == "authorization_pending":  # user has not finished yet: keep waiting
            continue
        if err == "slow_down":              # server asks us to poll less often
            interval += 5
            continue
        raise ExportError(f"Sign-in did not complete ({_aad_error(t)})")
    raise ExportError("Sign-in timed out; run `login` again.")


## @brief Client for the Power BI push-dataset REST API.
#  @details Handles access tokens transparently: the first API call exchanges
#  the stored refresh token for a short-lived access token, caches it in
#  memory, and renews it shortly before expiry.
class PowerBI:
    ## @brief Create a client.
    #  @param cfg Power BI / Entra settings.
    def __init__(self, cfg: PowerBIConfig) -> None:
        self.cfg = cfg
        self._http = make_client()
        self._token: str | None = None
        self._token_expires = 0.0  # time.monotonic() value at which the token lapses

    ## @brief Return a valid access token, refreshing it if needed.
    #  @details Entra usually *rotates* the refresh token on every use. The new
    #  one is written back to the token cache immediately; if it were not, the
    #  next run would fail with `invalid_grant`.
    #  @return A bearer access token for the Power BI API.
    #  @throws ExportError If never signed in, or the sign-in expired/was revoked.
    def _access_token(self) -> str:
        # Reuse the cached token unless it is within 30 s of expiring.
        if self._token and self._token_expires > time.monotonic() + 30:
            return self._token
        if not self.cfg.token_cache.is_file():
            raise ExportError("Not signed in to Power BI yet. Run `python t1ote_export_assets.py login` first.")
        refresh = json.loads(self.cfg.token_cache.read_text())["refresh_token"]
        r = self._http.post(
            f"{AUTHORITY}/{self.cfg.tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.cfg.client_id,
                "refresh_token": refresh,
                "scope": POWERBI_SCOPE,
            },
        )
        if r.status_code >= 400:
            raise ExportError(
                f"Power BI sign-in has expired or been revoked ({_aad_error(r)}). Run `login` again."
            )
        body = r.json()
        self._token = body["access_token"]
        self._token_expires = time.monotonic() + float(body.get("expires_in", 3600))
        new_refresh = body.get("refresh_token")
        if new_refresh and new_refresh != refresh:
            _save_refresh_token(self.cfg.token_cache, new_refresh)
        return self._token

    ## @brief Build a full API URL for the configured workspace.
    #  @param path Path below the workspace, e.g. `/datasets`.
    #  @return Full URL. With no `POWERBI_WORKSPACE_ID` the `/groups/<id>`
    #          segment is omitted, which targets "My workspace".
    def _url(self, path: str) -> str:
        prefix = f"/groups/{self.cfg.workspace_id}" if self.cfg.workspace_id else ""
        return f"{POWERBI_API}{prefix}{path}"

    ## @brief Send an authenticated request and turn failures into `ExportError`.
    #  @param method HTTP method.
    #  @param url Full URL.
    #  @param what Short phrase ("creating the dataset") used in error messages.
    #  @param kw Extra arguments for `httpx.Client.request` (e.g. `json=`).
    #  @return The successful (< 400) response.
    #  @throws ExportError On transport errors or HTTP >= 400, with a hint for
    #          the common 401/403 (permissions) and 404 (wrong id) cases.
    def _call(self, method: str, url: str, what: str, **kw: Any) -> httpx.Response:
        try:
            r = self._http.request(method, url, headers={"Authorization": f"Bearer {self._access_token()}"}, **kw)
        except httpx.HTTPError as e:
            raise ExportError(f"Could not reach Power BI while {what}: {e}") from e
        if r.status_code >= 400:
            hint = ""
            if r.status_code in (401, 403):
                hint = " (does your account have Contributor/Member access to the workspace?)"
            elif r.status_code == 404:
                hint = " (check POWERBI_WORKSPACE_ID / POWERBI_DATASET_ID / POWERBI_TABLE_NAME)"
            raise ExportError(f"Power BI error while {what}: HTTP {r.status_code} {r.text[:400]}{hint}")
        return r

    ## @brief Create the push dataset (one table).
    #  @param columns The table's columns (from `resolve_columns()`).
    #  @details Uses the `basicFIFO` retention policy, a safety net that caps the
    #  table at 200,000 rows (oldest dropped first). Note it is a **query-string**
    #  parameter on this endpoint; putting it in the JSON body is rejected with HTTP 400.
    #  @return The new dataset's GUID (store it as `POWERBI_DATASET_ID`).
    #  @throws ExportError On any Power BI failure.
    def create_dataset(self, columns: list[Column]) -> str:
        schema = [(c.name, c.dtype) for c in columns]
        url = self._url("/datasets") + "?defaultRetentionPolicy=basicFIFO"
        body = {
            "name": self.cfg.dataset_name,
            "defaultMode": "Push",
            "tables": [
                {
                    "name": self.cfg.table_name,
                    "columns": [{"name": n, "dataType": t} for n, t in schema],
                }
            ],
        }
        return self._call("POST", url, "creating the dataset", json=body).json()["id"]

    ## @brief Stop early if the dataset's table lacks a column that is about to be written.
    #  @details A push dataset's columns are fixed when it is created, so exporting a
    #  different column set needs a new dataset. This asks Power BI for the table's
    #  columns; if it cannot be read (or says nothing), the check is skipped and
    #  Power BI itself will reject a bad push.
    #  @param columns The columns that will be written.
    #  @throws ExportError If the table is missing any of them.
    def check_schema(self, columns: list[Column]) -> None:
        try:
            tables = self._call("GET", self._url(f"/datasets/{self.cfg.dataset_id}/tables"), "reading the dataset schema").json().get("value")
        except (ExportError, ValueError, AttributeError):
            return
        for t in tables if isinstance(tables, list) else []:
            if isinstance(t, dict) and t.get("name") == self.cfg.table_name and isinstance(t.get("columns"), list):
                have = {c.get("name") for c in t["columns"] if isinstance(c, dict)}
                missing = [c.name for c in columns if c.name not in have]
                if missing:
                    raise ExportError(
                        f"The Power BI table {self.cfg.table_name!r} has no column(s): {', '.join(missing)}. A push dataset's "
                        "columns are fixed when it is created: run `create-dataset` with the same column options, put the new "
                        "POWERBI_DATASET_ID in your .env, and re-run (then repoint reports at the new dataset)."
                    )

    ## @brief URL of the configured table's `rows` collection.
    #  @return Full URL for DELETE (clear) and POST (append) of rows.
    def _rows_url(self) -> str:
        return self._url(f"/datasets/{self.cfg.dataset_id}/tables/{self.cfg.table_name}/rows")

    ## @brief Delete every row in the configured table.
    #  @details Called before each export so Power BI always shows the *latest
    #  snapshot* rather than an ever-growing append log.
    #  @throws ExportError On any Power BI failure.
    def clear_table(self) -> None:
        self._call("DELETE", self._rows_url(), f"clearing table {self.cfg.table_name!r}")

    ## @brief Append rows to the configured table.
    #  @details Sends at most `PUSH_BATCH_ROWS` rows per request (Power BI's
    #  limit). Other service limits (rows per hour, requests per minute) are
    #  not handled here; an export at typical OT-site scale stays far below them.
    #  @param rows Row dicts from `build_rows()`.
    #  @return The number of requests (batches) sent.
    #  @throws ExportError On any Power BI failure.
    def push_rows(self, rows: list[dict[str, Any]]) -> int:
        batches = 0
        for i in range(0, len(rows), PUSH_BATCH_ROWS):
            chunk = rows[i : i + PUSH_BATCH_ROWS]
            self._call("POST", self._rows_url(), f"pushing rows {i + 1}-{i + len(chunk)}", json={"rows": chunk})
            batches += 1
        return batches


## @}
