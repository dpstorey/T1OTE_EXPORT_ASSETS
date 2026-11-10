# Tenable OT asset and software (SBOM) export

One command-line tool, **`t1ote_export_assets.py`**, reads from Tenable OT Security and produces:

- **assets**: every asset Tenable OT discovered, with all (or the columns you choose) of
  the Inventory-view columns (`assets` command).
- **software and CVEs**: the installed-software list Tenable OT collected from Windows
  hosts (WMI / OT Agent), mapped to CPE names, with the CVEs the
  [NVD](https://nvd.nist.gov/) says apply to each product **version** (`sbom` command).
- **`run`** does both with the same targets, scope and columns.
- **`suggest-map`** helps you improve the software-to-CPE mapping (see "Mapping products to CPEs"),
  and `--cyclonedx` writes the software inventory as a CycloneDX 1.6 BOM.

Results go to CSV/JSON files and, with `--powerbi`, into one Power BI dataset with three
related tables (`assets`, `sbom_software`, `sbom_findings`). It works against an
**Enterprise Manager (EM)**, a **standalone ICP**, or **several ICPs** listed in a config
file, and is **read-only** against Tenable: it only runs GraphQL queries. The code is in
`t1ote_core.py` (Tenable, columns, Power BI) and `t1ote_sbom.py` (software and NVD).

```
Tenable OT (EM, or one or more standalone ICPs)
   |  GraphQL
   +--> assets   --> assets_*.csv            --powerbi--> `assets`
   +--> sbom
          installed software per Windows host
          -> drop non-product noise (EDS / module profiles, SDK packs, docs)
          -> map name to CPE   (built-in table, your --map-file, optional --fuzzy)
          -> NVD API 2.0: CVEs for that CPE (cached, rate-limited)
          -> CSV + JSON: software inventory, findings, unmapped list
                                           --powerbi--> `sbom_software`, `sbom_findings`
   run = assets, then sbom
```

> **Read the results as inferred.** Windows reports product names as free text and the
> NVD identifies products by CPE, so matching is best-effort. Expect false positives and
> misses, and verify a finding on the host before acting on it. Every finding records how
> it was matched in `match_basis`.

## Requirements

- Python 3.10 or newer. The test suite passes on 3.11, 3.12 and 3.13, the scan has been
  run on 3.14, and 3.10 has only been syntax-checked.
- A Tenable OT Security Enterprise Manager or ICP, and an API key whose user may read
  assets. WMI (or OT Agent) data must actually have been collected for the hosts you
  want covered; see [Troubleshooting](#troubleshooting).
- Internet access to `services.nvd.nist.gov` (and to Microsoft / Power BI if you use it).
- Optional: a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key).

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then edit .env
```

## Connecting to Tenable

### One target

Put `TENABLE_URL` and `TENABLE_API_KEY` in `.env` (or the environment). The URL is the base
only, such as `https://icp.example.com`: no `/graphql`, no site id. The API key is the single
key generated in the OT console. It is **not** a Tenable One accessKey/secretKey pair.

There is deliberately no `--api-key` option: a key on the command line ends up in your
shell history and in the process list. Use `.env`, the environment, or a config file.

### Enterprise Manager or standalone ICP: detected automatically

The tool asks the server which it is (the `isEm` GraphQL field, and if that is not
available, a probe of an EM-only query), logs the answer, and behaves accordingly:

- **Standalone ICP:** everything is read from `<url>/graphql`. The data is labelled with
  the target's name (the config-file section, or the host name).
- **Enterprise Manager:** assets live under each paired site. If exactly one site is
  paired it is used automatically. Otherwise choose with `--site NAME`, or `--site all` for
  every paired site. You always give the site **name**; the tool looks up its id.

Authentication or connection failures are reported as such, never mistaken for "this is an
ICP". `--mode em` or `--mode icp` (or `TENABLE_MODE`) overrides detection if it ever guesses
wrong. `python t1ote_export_assets.py sites` shows what each target is and lists its site names.

### Several targets: a config file

For several ICPs with no EM, or a mix, describe them in a config file and pass
`--config`. Start from `targets.example.ini`:

```ini
[DEFAULT]
tls_verify = 0

[london]
url = https://london.example.com
api_key_env = LONDON_API_KEY

[sydney]
url = https://sydney.example.com
api_key = paste-the-key-here

[corporate-em]
url = https://em.example.com
api_key_env = EM_API_KEY
site = Head Office
```

- Each section is one target; its name labels that target's data in the `site` column.
- `api_key_env` reads the key from an environment variable, so the file need not hold it.
  If the file does hold keys, `chmod 600` it (the tool warns if others can read it) and keep
  it out of git (`targets.ini` is already in `.gitignore`).
- Optional keys: `site`, `mode`, `tls_verify`, `ca_bundle` (relative paths resolve against the
  file's folder). Put comments on their own lines.
- `--target NAME` (repeatable) uses only some sections. Without it, every section is used.
- `--url` cannot be combined with `--config`.

Asset ids from different targets are assumed to be distinct (they are random UUIDs). Data
from all targets ends up in the same tables, told apart by the `site` column.

## Running the SBOM scan (`sbom`)

Start with a dry run. It reads Tenable and maps products, but makes no NVD requests and
writes nothing:

```bash
python t1ote_export_assets.py sbom --dry-run
```

Then a real run:

```bash
python t1ote_export_assets.py sbom                                  # one ICP, or an EM with one site
python t1ote_export_assets.py sbom --site London                    # an EM site, by name
python t1ote_export_assets.py sbom --config targets.ini             # several targets
python t1ote_export_assets.py sbom --fuzzy --min-cvss 7 --kev-only
python t1ote_export_assets.py sbom --help
```

The first lines of a run tell you how much data there is, for example
`95 asset(s) scanned, 14 reported WMI data, 14 with software; ...`.

### sbom options

| Option | Effect |
|---|---|
| `--config`, `--target`, `--url`, `--site`, `--mode` | Which Tenable target(s) and site; see above. |
| `--subnet CIDR`, `--ip-range A-B` | Only assets with an IP in that range. |
| `--criticality-at-least {none,low,medium,high}` | Minimum asset criticality. |
| `--limit N` | Scan at most N assets **per site**. Assets come back in id order, so a small limit may miss the hosts that have software. |
| `--all-os` | Do not restrict to Windows hosts. Slower, and non-Windows assets carry no software list. |
| `--page-size N` | Assets per Tenable request (default 10; each Windows host is about 80 KB). |
| `--keep-noise` | Keep EDS / module-profile / SDK-pack / documentation entries that are normally dropped. |
| `--map-file FILE` | Your own product mappings (see below). |
| `--fuzzy` | For unknown products, try an NVD keyword search. Finds more, with more false positives, and costs one NVD request per unmapped product. |
| `--min-cvss X` | Drop CVEs scored below X (unscored CVEs are kept). |
| `--kev-only` | Keep only CVEs in CISA's Known Exploited Vulnerabilities list. |
| `--cyclonedx` | Also write `sbom_cyclonedx_<stamp>.json`, a CycloneDX 1.6 BOM: hosts as devices, software as applications, CVEs as vulnerabilities (state `in_triage`). Contains host names and IPs. No licences or hashes, so it is not a CRA-ready product SBOM. |
| `--cyclonedx-no-descriptions` | Leave CVE descriptions out of the CycloneDX file (each entry still links to the NVD). The file is always written compact; use this if a tool rejects a file for size (some validators stop at 5 MB). `--min-cvss` and `--kev-only` also shrink it. |
| `--sbom-author` | Who is responsible for the CycloneDX SBOM: `Name <email>`, or a name or URL (env `SBOM_AUTHOR`). Written as `metadata.authors`; left out if not set. |
| `--product-name`, `--product-version` | What the BOM describes, such as your site or system (env `SBOM_PRODUCT_NAME`, `SBOM_PRODUCT_VERSION`). Default: "Tenable OT installed-software inventory", versioned by the BOM's date. |
| `--out-dir DIR`, `--cache-dir DIR` | Where reports go (default `./t1ote_out`) and the NVD cache (default `./.sbom_cache`). |
| `--dry-run` | Collect and map only. |
| `--powerbi` | Also replace the Power BI `sbom_software` and `sbom_findings` tables. |

Other commands: `login`, `create-dataset` (Power BI one-time setup). Global options:
`--env-file FILE`, `--version`.

## Exporting assets

```bash
python t1ote_export_assets.py sites                 # what each target is, and its site names
python t1ote_export_assets.py assets --dry-run      # fetch and summarise, touch nothing
python t1ote_export_assets.py assets                # write assets_*.csv
python t1ote_export_assets.py assets --powerbi      # ...and replace the Power BI `assets` table
python t1ote_export_assets.py assets --config targets.ini --subnet 10.253.10.128/25
```

`assets` takes the same connection, scope and output options as `sbom` (`--subnet`, `--ip-range`,
`--criticality-at-least`, `--limit` per site, `--out-dir`, `--powerbi`, `--dry-run`). With several targets it
fetches all of them, writes one CSV, and with `--powerbi` clears the table **once** and pushes everything. `run` does `assets` then `sbom`.

### Choosing columns

By default every Tenable OT Inventory-view column is exported. To limit them:

```bash
python t1ote_export_assets.py columns                          # what can be exported from this Tenable
python t1ote_export_assets.py assets --export-columns name,vendor,ips,serial,last_seen
```

or put a comma-separated list in `.env` (an option on the command line overrides it):

```
TENABLE_EXPORT_COLUMNS=name,vendor,model,ips,macs,segments,purdue_level,last_seen
# TENABLE_EXPORT_COLUMNS=all
```

- Names may be written as shown by `columns` (`last_seen`) or as Tenable's field (`lastSeen`).
  `asset_id`, `site` and `exported_at` are always included.
- `all` means the Tenable OT Inventory-view columns (name, type, vendor, model, OS, firmware,
  serial, slot, criticality, risk, Purdue level, IPs, MACs, segments, sources, tags, backplane,
  run status, lifecycle, first/last seen, custom fields 1-10, and so on). Columns this Tenable
  version does not have are skipped. Lists (IPs, tags, segments...) become one comma-separated cell.
  Large nested structures (`details`, `layout`) are not exportable as columns.
- Custom fields take the names set in the OT console: a field named "Cost Centre" becomes the
  column `Cost Centre` (case and spaces are kept; Power BI allows both). An unnamed field (or a
  name that clashes with another column) stays `custom_field_<n>`. When selecting, any spelling
  works (`Cost Centre`, `cost_centre`, `custom_field_2`); in a list, separate columns with commas only. Fields beyond the first 10 are picked up
  automatically when the Tenable version has them.
- **A push dataset's columns are fixed when it is created.** Run `create-dataset` with the
  *same* column options, put the new `POWERBI_DATASET_ID` in `.env`, then `assets --powerbi` again (and
  `sbom --powerbi`, which fills the other two tables). An `assets --powerbi` run whose columns are missing from
  the existing table stops before clearing it and says so.
- `create-dataset` with column options reads the field list from Tenable, so it needs the same
  connection settings as `assets`.

## SBOM output

Files are written to `--out-dir` with a timestamp:

- `sbom_software_<stamp>.csv` / `.json`: the **software inventory**, one row per product
  version on a host, mapped or not. Columns: `software_id, asset_id, asset_name, site,
  product, version, cpe, cpe_product, match_basis, status, reason, cve_count, max_cvss,
  kev_count`.
  `status` is `mapped`, `unmapped`, or `cpe_not_in_nvd`.
- `sbom_cves_<stamp>.csv` / `.json`: the **findings**, one row per host, product version and
  CVE. Columns: `site, asset_id, software_id, asset_name, ips, product, version, cpe,
  cpe_product, match_basis, cve_id, cvss_score, severity, kev, published, description`.
- `sbom_unmapped_<stamp>.csv`: product versions that could not be mapped, with the reason
  and number of hosts. Use it to see the coverage gap and to build a `--map-file`.

`software_id` is a stable id for one product version on one host. It links a finding to its
software row, and the software row's `asset_id` links to the asset.

`match_basis` says how the product was mapped: `curated` (built-in table), `user_map`
(your `--map-file`), or `nvd_keyword` (`--fuzzy`). A `+version_trimmed` suffix means NVD did
not know the exact version string, so a shortened spelling was used (for example `9.20.00.0`
reported by Windows, `9.20` known to NVD). Treat `nvd_keyword` matches as leads to check.

CVSS scores prefer v4.0, then v3.1, v3.0, v2. `kev` is true when CISA lists the CVE as
known-exploited. CSV cells that start with `=`, `+`, `-` or `@` are prefixed with `'` so
third-party text cannot run as a spreadsheet formula.

## Fragments and duplicate findings

Some products install as many small packages (Visual C++ runtimes, TIA Portal support
packages, SQL Server components). Once mapped, each piece resolves to the same CPE product and
carries the same CVEs, so one host can show the same CVE several times in `sbom_findings`.

The tool keeps the inventory and findings **complete** and does not remove rows. Instead
every software and finding row has `cpe_product` (`vendor:product`, no version), the exact
key for all pieces of one product. De-duplicate where you analyse the data:

- **Power BI.** Count distinct things rather than rows:
  - `Distinct CVEs = DISTINCTCOUNT(sbom_findings[cve_id])`
  - `Exposed hosts = DISTINCTCOUNT(sbom_findings[asset_id])`
  - `Host-CVE pairs = COUNTROWS(SUMMARIZE(sbom_findings, sbom_findings[asset_id], sbom_findings[cve_id]))`

  Use the pairs measure for "how many things to fix". Add `cpe_product` to a table or slicer
  to see per-product exposure without the fragments.
- **SQL.** `SELECT DISTINCT asset_id, cve_id, cpe_product FROM sbom_findings`, or
  `GROUP BY asset_id, cve_id, cpe_product` with `COUNT(*)` for the number of contributing pieces.
- **Excel / CSV.** Remove duplicates on `asset_id`, `cve_id` and `cpe_product`.

To reduce fragments at the source, run `suggest-map`; its review sheet has a `fragment_hint`
column marking likely build pieces. For those, leaving the piece unmapped (no findings) is
often better than mapping it to the parent product. Map only the entry that represents the
product itself.

CycloneDX output already lists each CVE once, however many components it affects.

### What the CycloneDX file is, and what a validator will say

The BOM is an **installed-software inventory** of your OT hosts, not the SBOM of a product you
ship. It records the author, the thing described (`metadata.component`), a dependency tree
(product -> hosts -> software), `lifecycles: operations`, and a `compositions` entry marked
`incomplete`, because only Windows installed-software lists are visible and noise packages are
dropped. Vulnerabilities are `in_triage`.

Tenable OT does not report file names, SHA-512 hashes, licences, or the executable, archive
and structured properties, and the tool does not invent them. Checkers built for shipped
products (BSI TR-03183-2, CISA 2026 elements) will therefore mark those fields as missing. That is
expected for an inventory, not a defect in the export. Component identifiers (CPE) rise as
you map more products, and `--vendor-file` supplies supplier and manufacturer names.
Firmware versions of devices appear only if the data source provides them.

## Mapping products to CPEs

Windows software names are free text, so the tool needs a name-to-CPE mapping.

1. **Built-in table** for common products: Chrome, Edge, Wireshark, Npcap, TightVNC,
   VMware Tools, 7-Zip, PuTTY, CodeMeter and several Rockwell engineering tools.
2. **Your `--map-file`**, a JSON object of `{regex: [vendor, product]}`. The regex is matched
   against the lower-case product name with the architecture and version words removed:

   ```json
   {
     "^abb 800xa": ["abb", "800xa"],
     "^activestate activepython": ["activestate", "activepython"]
   }
   ```

   Your entries are tried before the built-in table. Check vendor and product names against
   the [NVD CPE dictionary](https://nvd.nist.gov/products/cpe/search).
3. **`--fuzzy`** as a last resort.

**Drafting a map file.** Windows reports no publisher, so the vendor has to be read from the
name. `suggest-map` does that for the products `sbom` left unmapped:

```bash
python t1ote_export_assets.py suggest-map t1ote_out/sbom_unmapped_<stamp>.csv
```

It recognises the vendor from the name (Microsoft, Siemens, Rockwell Automation, ABB, National
Instruments and others), then checks the NVD CPE dictionary and proposes a mapping **only when
the NVD lists a product for that vendor whose name appears in the product name**. It writes a
review sheet (`sbom_mapping_review_<stamp>.csv`: what it recognised, what it proposed, why not,
and the NVD candidates it saw) and a draft `sbom_mapping_suggestions_<stamp>.json`. Delete any
entry you disagree with, then use it: `sbom --map-file sbom_mapping_suggestions_<stamp>.json`.
Only product names are sent to the NVD; `--dry-run` sends nothing and just recognises vendors.

**Your own vendor list (`--vendor-file`).** For names the built-in prefixes do not recognise,
supply a CSV or tab-separated file with `Title` and `Vendor` columns (see `vendors.tsv`). A
trailing version in the title is ignored. `suggest-map --vendor-file` uses it as the vendor
shown in the review sheet, and `sbom --cyclonedx --vendor-file` writes it as the component's
`supplier`, marked `t1ote:supplier_basis = vendor_file` so nobody mistakes it for something
Tenable reported. Nothing is invented for products that are not in the file.

You do not need to pass the option: if `--vendor-file` is not given, the tool uses the file named
by `TENABLE_VENDOR_FILE`, else `vendors.tsv` next to the script or in the current folder, and
prints which one it used. `--vendor-file none` turns it off.
It makes up to two NVD requests per distinct product name, so set `NVD_API_KEY`.

NVD's dictionary is thin for industrial software, so many components will stay unmapped
however you configure the tool. For those, the vendor's own advisories are the authoritative
source.

**Noise.** A Rockwell engineering host can list hundreds of module profiles, EDS files, SDK
and language packs, documentation and media components. They carry no CVEs of their own and
are dropped by default (`--keep-noise` keeps them).

## NVD rate limits, caching and progress

- Without an API key the tool waits about 6.5 s between NVD requests; with a key about 0.7 s.
  A first run over a large estate is slow without a key.
- Each distinct product version is looked up once, however many hosts have it.
- Answers are cached in `.sbom_cache/` for 7 days. Progress is printed and the cache is saved
  every 25 NVD requests, so an interrupted run (Ctrl-C) keeps its work.
- `--fuzzy` makes one keyword search per unmapped product, so it takes noticeably longer.

## Power BI (optional)

Both tools write into **one push dataset with three tables**, so Power BI can relate them:

```
assets [asset_id] 1 ---- * sbom_software [asset_id]
                          sbom_software [software_id] 1 ---- * sbom_findings [software_id]
```

Drill from an asset, to the software on it, to that software's CVEs. In a visual,
the CVEs appear as rows under their software row.

**One-time setup** (needs a Microsoft Entra app registration with public client flows
allowed, and an account with access to the workspace):

```bash
# put AZURE_TENANT_ID, AZURE_CLIENT_ID (and POWERBI_WORKSPACE_ID) in .env first
python t1ote_export_assets.py login             # Microsoft device sign-in; stores a refresh token
python t1ote_export_assets.py create-dataset    # prints POWERBI_DATASET_ID=... for your .env
```

`create-dataset` defines the three tables and the two relationships. If Power BI refuses the
relationships, run it again with `--no-relationships` and relate the columns shown above in
the Power BI model view (one-to-many, from the `assets` side). 

**Each refresh:**

```bash
python t1ote_export_assets.py run --powerbi      # fills `assets`, then `sbom_software` and `sbom_findings`
# or separately: `assets --powerbi` and `sbom --powerbi`
```

- Each command **replaces** its own tables with the latest results, so a scoped run
  (`--subnet`, `--limit`, `--target`) replaces a full one. The tables refresh independently.
- The CSV and JSON files are written first; if the push fails they are kept and the error
  says so. `--dry-run` never pushes.
- A push dataset's schema is fixed at creation. To change a table's columns (including with
  `--export-columns`), create a new dataset and update `POWERBI_DATASET_ID`.
- Unlike the NVD lookups, Power BI receives host names and IP addresses, so choose the
  workspace and its sharing accordingly.

## Privacy and safety

- Only **product names and versions** are sent to the NVD. Host names, IP addresses and asset
  ids never leave your network, except to the Power BI workspace if you use it.
- Credentials come from `.env`, the environment or a config file. `.env`, `targets.ini`, the
  Power BI token file, scan output and the NVD cache are listed in `.gitignore`; keep them out
  of version control.
- TLS to the NVD is always verified. For Tenable, prefer a CA bundle (`TENABLE_CA_BUNDLE` or
  `ca_bundle`) over turning verification off.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Multiple sites are paired (...)` | An Enterprise Manager with several sites: pass `--site NAME` or `--site all`. |
| `No site named ...` | Check the spelling against `python t1ote_export_assets.py sites`. |
| `HTTP 401/403` from Tenable | Wrong API key, or its user cannot read assets. |
| `CERTIFICATE_VERIFY_FAILED` | Private CA: set `TENABLE_CA_BUNDLE` (or `TENABLE_TLS_VERIFY=0` for a lab). |
| Detection picks the wrong type | Force it with `--mode em` or `--mode icp`. |
| `0 reported WMI data` | None of the scanned Windows hosts has WMI data in Tenable. Check an asset's Details tab; the first assets returned may all be passively seen, so try without `--limit`. |
| WMI hosts found but `0 with software` | The ICP collected WMI facts but no installed-software table (collection disabled or unsupported on that version). |
| Very slow | No `NVD_API_KEY`, or `--fuzzy` on a large unmapped list. |
| `Unmapped: ...` is long | Expected for industrial software; see "Mapping products to CPEs". |
| Power BI rows missing for some hosts | Each command replaces its own tables; run `run --powerbi` with the same scope. |

## About the data, and how to improve it

What you get is an **inventory of installed software with inferred vulnerabilities**. It is
useful, and it is not an authoritative product SBOM or a vulnerability assessment. Know these
limits before you hand the results to anyone.

- **Software comes from Windows hosts only**, from the installed-software list Tenable OT
  collects. That list has a name, a version and an install date, with no vendor, file names,
  hashes or licences. Firmware, PLC code, Linux and network devices are not covered.
- **Matching is inferred.** Names are free text; the NVD identifies products by CPE. Only
  products the tool can map get findings. Everything else is listed as unmapped, never silently
  dropped. A typical run maps a minority of the software list (the identifier count in
  the CycloneDX file shows your own coverage).
- **Findings are possible, not confirmed.** A CVE is listed when the NVD says it applies to
  that product version. Reachability, mitigations and patches the vendor backported are not
  considered. CycloneDX findings are marked `in_triage`.
- **Fragments inflate row counts.** Products that install as many pieces (Visual C++, TIA
  Portal, SQL Server) can repeat the same CVE on one host. See "Fragments and duplicate
  findings" for how to count correctly.
- **The CycloneDX file is an inventory BOM.** It meets the CRA Annex I Part II(1) minimum as
  far as a document can show, but not the build-artefact fields (hashes, file names,
  licences) that checkers such as BSI TR-03183-2 look for. It is not a conformity statement.
- **Time matters.** The NVD changes daily; results are as of the run (`exported_at`). Cached
  NVD answers are trusted for 7 days.

**How to improve coverage, in order of payoff:**

1. Run `sbom`, then `suggest-map` on the `sbom_unmapped_*.csv`, review the sheet, keep the
   entries that are right, and pass the file back with `--map-file`. A ready-made starter is
   in `sbom_map.json`. Leave build fragments unmapped.
2. Fill in `vendors.tsv` (used by default) so components carry a supplier name.
3. Use `--fuzzy` for leads on what is still unmapped. Treat `nvd_keyword` matches as leads to check.
4. Set `NVD_API_KEY`; it is free and makes NVD lookups about ten times faster.
5. Re-run on a schedule so the findings follow the NVD.

## Limitations

- Results are inferred from product names and versions (see the note at the top).
- Windows hosts only; software on other operating systems is not collected.
- Operating-system and Microsoft patch levels (hotfixes / KBs) are not assessed.
- Products without an NVD CPE entry cannot be matched.
- Matching uses published CVE data, not whether a vulnerable component is reachable or already
  mitigated on the host.

## Tests

No network or credentials needed, and a real `.env` is never read:

```bash
python -m unittest discover -s tests -v
```

## Licence

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). This is a community
project provided as-is and is not an officially supported Tenable product.
