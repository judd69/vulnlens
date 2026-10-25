# OSV.dev fixture for the VulnLens sample report

`sample-batch-response.json` has the exact shape of a live
`POST https://api.osv.dev/v1/querybatch` response (`{"results":[{"vulns":[...]}, …]}`,
one entry per queried dependency, in pom order) for
`examples/vulnerable-sample/pom.xml`.

## Provenance — read this before regenerating

Every record in the fixture is a **real OSV.dev record fetched live on
2026-10-24** (`GET https://api.osv.dev/v1/vulns/<id>`), and each one was
individually verified to affect the pinned sample version by checking its
`affected[].ranges[]` ECOSYSTEM/SEMVER events (introduced ≤ version < fixed).
Nothing here is fabricated or hand-written.

Why a fixture instead of a live batch call? The build sandbox used for this
run blocks all HTTP POST request bodies at the egress proxy (GETs pass), and
the JVM is additionally denied raw TCP by the runtime's network policy — so
`querybatch` (POST-only) is unreachable from *this* sandbox. On any normal
network VulnLens queries the live API directly (see `OsvClient`). The fixture
lets `tools/gen-sample-report.sh` regenerate `docs/sample-report.html`
offline through VulnLens's own `OsvMapper` → `ScanEngine` → `HtmlReport`
pipeline — the only thing bypassed is the HTTP transport.

## Records (query order = pom order)

| # | dependency | version | CVE (verified affected) |
|---|------------|---------|--------------------------|
| 1 | org.apache.logging.log4j:log4j-core | 2.14.1 | CVE-2021-44228, CVE-2021-45046, CVE-2021-45105, CVE-2021-44832 |
| 2 | org.apache.commons:commons-text | 1.9 | CVE-2022-42889 |
| 3 | org.springframework:spring-webmvc | 5.2.0.RELEASE | CVE-2022-22965 |
| 4 | com.fasterxml.jackson.core:jackson-databind | 2.9.9 | CVE-2019-14379, CVE-2020-8840, CVE-2019-14439, CVE-2019-16335, CVE-2020-9546, CVE-2020-9548 |
| 5 | org.apache.struts:struts2-core | 2.3.24 | CVE-2017-5638, CVE-2018-11776 |
| 6 | commons-collections:commons-collections | 3.2.1 | CVE-2015-7501 |

To re-verify any record: `curl https://api.osv.dev/v1/vulns/<CVE-or-GHSA-id>`.
