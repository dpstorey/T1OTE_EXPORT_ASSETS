-- Starter queries for Metabase (New -> SQL query -> pick the database -> run -> Save).
-- They read the tables the tool writes (schema t1ote, or your --db-schema).
-- Count from sbom_exposure rather than sbom_findings: it lists each CVE once per host and
-- product family (cpe_product), so fragments of one product do not inflate the numbers.


-- 1. Exposure at a glance (single row; works as a table or a set of numbers)
SELECT
  count(DISTINCT cve_id)                  AS distinct_cves,
  count(DISTINCT asset_id)                AS exposed_hosts,
  count(*)                                AS host_cve_pairs,
  count(*) FILTER (WHERE cvss_score >= 9) AS critical_pairs,
  count(*) FILTER (WHERE kev)             AS known_exploited_pairs
FROM t1ote.sbom_exposure;


-- 2. Known-exploited (CISA KEV) findings by host (bar chart: asset_name x kev_findings)
SELECT asset_name, count(*) AS kev_findings, max(cvss_score) AS worst_cvss
FROM t1ote.sbom_exposure
WHERE kev
GROUP BY asset_name
ORDER BY kev_findings DESC
LIMIT 20;


-- 3. How much of the installed software could be matched (pie or bar on status)
--    status: mapped, unmapped, cpe_not_in_nvd. "unmapped" is the coverage gap.
SELECT status, count(*) AS software_rows, count(DISTINCT product) AS distinct_products
FROM t1ote.sbom_software
GROUP BY status
ORDER BY software_rows DESC;


-- 4. Products behind the most exposure
SELECT cpe_product, count(DISTINCT cve_id) AS distinct_cves, count(DISTINCT asset_id) AS hosts
FROM t1ote.sbom_exposure
GROUP BY cpe_product
ORDER BY distinct_cves DESC
LIMIT 15;


-- 5. Exposure by site (add `site` to any query and GROUP BY it to use a site filter)
SELECT site, count(DISTINCT asset_id) AS exposed_hosts, count(DISTINCT cve_id) AS distinct_cves
FROM t1ote.sbom_exposure
GROUP BY site
ORDER BY distinct_cves DESC;
