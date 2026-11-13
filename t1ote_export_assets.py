#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
## @file t1ote_export_assets.py
#  @brief Tenable One OT Exposure -> assets, installed software and CVEs, to files and Power BI.
#
#  @details
#  One command-line tool for the whole data flow:
#  @code{.unparsed}
#      Tenable EM / ICP --GraphQL--> assets ------------------------> assets table
#                                    installed software --NVD--> sbom_software, sbom_findings
#  @endcode
#
#  | Command          | Purpose                                                                  |
#  |------------------|--------------------------------------------------------------------------|
#  | `sites`          | Show whether each target is an EM or an ICP; list its sites.             |
#  | `columns`        | List the asset columns that can be exported, and which are selected.     |
#  | `login`          | One-time Microsoft sign-in (device code flow) for Power BI.              |
#  | `create-dataset` | One-time creation of the Power BI dataset (assets, sbom_software, sbom_findings). |
#  | `assets`         | Export the assets (CSV; with `--powerbi`, also replace the `assets` table). |
#  | `sbom`           | Software -> CVEs from the NVD (CSV/JSON; with `--powerbi`, the two SBOM tables). |
#  | `suggest-map`    | Draft a `--map-file` for unmapped products, checked against the NVD.   |
#  | `run`            | `assets` then `sbom`, with the same targets, scope and columns.          |
#
#  The same options mean the same thing on every command: connection (`--config`, `--url`,
#  `--site`...), scope (`--subnet`, `--ip-range`, `--criticality-at-least`, `--limit`),
#  columns, and output (`--out-dir`, `--powerbi`, `--dry-run`). Settings (URLs, keys, GUIDs)
#  come from `.env`; see README.md and `.env.example`.
#
#  Code lives in `t1ote_core.py` (Tenable, columns, Power BI) and `t1ote_sbom.py`
#  (software, NVD, CVE report); this file is only the command line.
#
#  @author Reference implementation, supplied as-is for evaluation.
#  @copyright Licensed under the Apache License, Version 2.0 (see LICENSE).
#  @version 0.2.0

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

import t1ote_core as hx
import t1ote_sbom as sbom
import t1ote_sql as sq
from t1ote_core import ExportError, log

## @brief Program version, shown by `--version`.
__version__ = hx.__version__


## @brief `sites`: show what each configured target is and list its paired sites.
#  @param args Parsed arguments (connection options).
#  @return 0 on success, 1 if an Enterprise Manager has no paired sites.
def cmd_sites(args: argparse.Namespace) -> int:
    status = 0
    for cfg in hx.load_targets(args):
        tenable = hx.Tenable(cfg)
        if tenable.detect_mode() == "icp":
            print(f"{cfg.name}: standalone ICP (no sites; use it directly)")
            continue
        sites = tenable.paired_sites()
        if not sites:
            print(f"{cfg.name}: Enterprise Manager with no paired sites.")
            status = 1
            continue
        print(f"{cfg.name}: Enterprise Manager, {len(sites)} site(s):")
        for site in sorted(sites, key=lambda x: x["name"].lower()):
            print(f"  {site['name']}")
    return status


## @brief `columns`: list the exportable columns for each target.
#  @details Shows the Inventory-view hx.catalogue with each column's hx.Tenable field and Power BI
#  type, marks any the server does not have, lists extra scalar fields the server offers,
#  and shows what the current options / `TENABLE_EXPORT_COLUMNS` would export.
#  @param args Parsed arguments (connection and column options).
#  @return 0 on success.
def cmd_columns(args: argparse.Namespace) -> int:
    spec = hx.columns_spec(args)
    for cfg in hx.load_targets(args):
        tenable = hx.Tenable(cfg)
        site_id = tenable.sites_to_scan()[0][0]
        fields = tenable.asset_fields(site_id)
        names = tenable.custom_fields(site_id)
        print(f"{cfg.name}: " + ("server schema read." if fields else "the server did not describe its asset type; availability unknown."))
        print("Inventory columns (--export-all-columns exports these):")
        for c in hx.catalogue(fields, names):
            gone = fields is not None and c.path and c.path[0] not in fields
            print(f"  {c.name:<22} {'.'.join(c.path):<22} {c.dtype:<8}{'  (not on this server)' if gone else ''}")
        extra = hx.extra_columns(fields)
        if extra:
            print("Other fields this server offers (name them in --export-columns):")
            for f, c in extra.items():
                print(f"  {c.name:<22} {f:<22} {c.dtype}")
        cols = hx.resolve_columns(spec, fields, names)
        print(f"Selected ({len(cols)}{', all' if spec == 'all' else ''}): {', '.join(c.name for c in cols)}")
    return 0


## @brief `login`: run the one-time Microsoft sign-in.
def cmd_login(args: argparse.Namespace) -> int:
    hx.device_login(hx.PowerBIConfig.from_env(need_dataset=False))
    return 0


## @brief `create-dataset`: create the combined Power BI dataset and print its id.
#  @details Does not edit `.env`; it prints the line to add. The columns come from Tenable (all
#  Inventory-view columns unless limited), so this needs the Tenable connection settings.
def cmd_create_dataset(args: argparse.Namespace) -> int:
    cfg = sbom.sbom_powerbi_config(need_dataset=False)
    columns = hx.resolve_selected_columns(args)
    dataset_id = sbom.SbomPowerBI(cfg).create_dataset(columns, relationships=not args.no_relationships)
    print(
        f"Created dataset {cfg.dataset_name!r} ({len(columns)} asset columns) with tables "
        f"{cfg.table_name!r}, {sbom.SOFTWARE_TABLE!r} and {sbom.FINDINGS_TABLE!r}."
    )
    print("Add this line to your .env file:")
    print(f"POWERBI_DATASET_ID={dataset_id}")
    if args.no_relationships:
        print(
            "No relationships were defined. In Power BI model view relate "
            f"{cfg.table_name}[asset_id] -> {sbom.SOFTWARE_TABLE}[asset_id] and "
            f"{sbom.SOFTWARE_TABLE}[software_id] -> {sbom.FINDINGS_TABLE}[software_id] (one-to-many)."
        )
    return 0


## @brief `assets`: fetch assets from Tenable, write a CSV, and (with `--powerbi`) replace the Power BI table.
#  @details Steps: validate the scope and settings -> resolve the target(s), columns and site(s)
#  -> page the assets -> shape rows -> write the CSV -> (with `--powerbi`) clear the table once and
#  push the rows of *all* targets. Everything is validated first so a typo fails before any network call.
#  @param args Parsed arguments: connection, scope, column and output options.
#  @return 0 on success.
#  @throws ExportError On invalid scope or any Tenable / Power BI failure.
def cmd_assets(args: argparse.Namespace) -> int:
    if args.limit is not None and args.limit < 1:
        raise ExportError("--limit must be a positive number.")
    filt = hx.build_filter(args.criticality_at_least, args.subnet, args.ip_range)
    clients = [hx.Tenable(cfg) for cfg in hx.load_targets(args)]
    pbi = hx.PowerBI(sbom.sbom_powerbi_config(need_dataset=True)) if args.powerbi and not args.dry_run else None
    columns = hx.resolve_selected_columns(args, clients)
    log(f"Exporting {len(columns)} column(s)" + ("" if hx.columns_spec(args) == "all" else f": {', '.join(c.name for c in columns)}"))
    if pbi is not None:
        pbi.check_schema(columns)

    rows: list[dict[str, Any]] = []
    for tenable in clients:
        for site_id, site_label in tenable.sites_to_scan():
            log(f"Site: {site_label}" + (f" ({site_id})" if site_id else " (standalone ICP)"))
            log("Fetching assets from Tenable...")
            total, nodes = tenable.fetch_assets(site_id, filt, args.limit, columns)
            rows.extend(hx.build_rows(nodes, site_label, columns))
            log(f"  {len(nodes)} asset(s) from {site_label} (Tenable reports {total} matching).")
    log(f"Fetched {len(rows)} asset(s) in total.")

    if args.dry_run:
        print(f"[dry run] {len(rows)} asset row(s) would be written. First rows:")
        for r in rows[:3]:
            print("  " + json.dumps(r))
        return 0

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"assets_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    sbom.write_csv(path, [c.name for c in columns], rows)
    print(f"Assets: {len(rows)} row(s) written to {path}")
    if pbi is not None:
        try:
            log(f"Replacing contents of Power BI table {pbi.cfg.table_name!r}...")
            pbi.clear_table()
            batches = pbi.push_rows(rows)
        except ExportError as e:
            raise ExportError(f"The assets file above was written, but the Power BI push failed: {e}") from e
        print(f"Power BI: {len(rows)} asset(s) written to {pbi.cfg.table_name!r} in {batches} batch(es).")
    sink = getattr(args, "sink", None)
    if sink is not None:
        try:
            log("Replacing PostgreSQL table 'assets'...")
            n = sink.replace_table(sq.assets_table(columns), rows)
            sink.checkpoint()
        except Exception as e:
            raise ExportError(f"The assets file above was written, but the PostgreSQL write failed (nothing was changed): {e}") from e
        print(f"PostgreSQL: {n} asset(s) written to schema {sink.schema!r}" + (f"; script {args.sql_out}" if args.sql_out else "") + ".")
    return 0


## @brief `sbom`: collect installed software, look up CVEs, write the report.
def cmd_sbom(args: argparse.Namespace) -> int:
    return sbom.run_sbom(args)


## @brief `suggest-map`: draft a mapping file for the products `sbom` could not map.
def cmd_suggest_map(args: argparse.Namespace) -> int:
    return sbom.run_suggest_map(args)


## @brief `run`: `assets` then `sbom`, with the same targets, scope and columns.
#  @details Assets go first (it is quick, and a Power BI or column problem shows up before the long
#  NVD run). The two tables refresh independently; if `sbom` fails, the assets table is already current.
def cmd_run(args: argparse.Namespace) -> int:
    code = cmd_assets(args)
    return code or cmd_sbom(args)


## @brief Build the command-line argument parser.
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="t1ote_export_assets.py",
        description="Export Tenable OT assets, installed software and CVEs to files and Power BI.",
    )
    p.add_argument("--env-file", default=None, help="Path to the .env file (default: .env next to this script, then the current directory).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name: str, func: Any, help: str, *, scope: bool = False, columns: bool = False, software: bool = False, output: bool = False) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help, description=help)
        hx.add_connection_args(sp)
        if scope:
            hx.add_scope_args(sp)
        if columns:
            hx.add_column_args(sp)
        if software:
            sbom.add_sbom_args(sp)
        if output:
            hx.add_output_args(sp)
            sq.add_db_args(sp)
        sp.set_defaults(func=func)
        return sp

    add("sites", cmd_sites, "Show whether each target is an Enterprise Manager or an ICP, and list its sites.")
    add("columns", cmd_columns, "List the columns that can be exported from this Tenable, and which are selected.", columns=True)
    sub.add_parser("login", help="One-time Microsoft sign-in for Power BI.").set_defaults(func=cmd_login)
    cd = add("create-dataset", cmd_create_dataset, "Create the Power BI dataset (assets, sbom_software, sbom_findings) and print its id.", columns=True)
    cd.add_argument("--no-relationships", action="store_true", help="Create the tables only; relate them yourself in Power BI model view.")
    add("assets", cmd_assets, "Export assets to a CSV and, with --powerbi, replace the Power BI assets table.", scope=True, columns=True, output=True)
    add("sbom", cmd_sbom, "Look up CVEs for the software on Windows hosts; write CSV/JSON and, with --powerbi, the SBOM tables.", scope=True, software=True, output=True)
    sm = sub.add_parser(
        "suggest-map",
        help="Draft a --map-file for unmapped products, checked against the NVD CPE dictionary.",
        description="Reads an sbom_unmapped_*.csv. Only product names are sent to the NVD. Writes a review sheet and a draft map file; nothing is applied until you pass the (edited) file to `sbom --map-file`.",
    )
    sm.add_argument("unmapped", metavar="UNMAPPED_CSV", help="The sbom_unmapped_<stamp>.csv written by `sbom`.")
    sm.add_argument("--out-dir", default="t1ote_out", help="Where to write the review sheet and draft map (default ./t1ote_out).")
    sm.add_argument("--cache-dir", default=".sbom_cache", help="NVD answer cache (default ./.sbom_cache).")
    sm.add_argument("--vendor-file", metavar="FILE", help="CSV/TSV with Title and Vendor columns: your own product -> vendor list for names the built-in prefixes do not recognise.")
    sm.add_argument("--dry-run", action="store_true", help="Recognise vendors only; make no NVD requests and write only the review sheet.")
    sm.set_defaults(func=cmd_suggest_map)
    add("run", cmd_run, "Run `assets` then `sbom` with the same targets and scope.", scope=True, columns=True, software=True, output=True)
    return p


## @brief Program entry point.
#  @details Loads the `.env` file, runs the chosen command, and maps outcomes to exit codes:
#  0 success, 1 expected error (`ExportError`), 2 bad `--env-file`, 130 Ctrl-C.
#  @param argv Argument list (defaults to `sys.argv[1:]`); a parameter so tests can call `main([...])`.
def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.env_file:
        if not Path(args.env_file).is_file():
            print(f"Error: env file {args.env_file!r} not found.", file=sys.stderr)
            return 2
        load_dotenv(args.env_file)
    else:
        # Script directory first, then the current directory. load_dotenv never overrides
        # a variable that is already set, so real environment variables always win.
        load_dotenv(Path(__file__).resolve().parent / ".env")
        load_dotenv(Path.cwd() / ".env")
    sink = None
    ok = False
    try:
        sink = args.sink = sq.open_sink(args)
        code = args.func(args)
        ok = code == 0
        return code
    except ExportError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    finally:
        if sink is not None:
            sink.finish(ok)


if __name__ == "__main__":
    sys.exit(main())
