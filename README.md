# VulnLens 🔍🛡️

**X-ray your Maven supply chain against the live OSV.dev vulnerability database.**

Most application code isn't yours — it's your dependencies. Log4Shell, Text4Shell
and Spring4Shell all hit projects through versions everyone had pinned years
earlier. VulnLens answers one question fast: *which of my dependencies have
known CVEs right now, how bad are they, and what do I upgrade to?*

Point it at any `pom.xml` (or project directory) and it queries
[OSV.dev](https://osv.dev) — Google's free, no-auth vulnerability database —
then produces a risk score, a severity heatmap, a sortable CVE table and
per-dependency upgrade suggestions.

Day 6 of the [Lens arc](https://github.com/judd69): AIGuard audits your code,
JarLens audits your jars, CinderLens audits your speed, RepoScope audits any
repo — **VulnLens audits your supply chain.**

## Requirements

- Java 17+ (built with 21; no other dependencies — the shipped jar is pure `javac` output)
- Network access to `https://api.osv.dev` at scan time

## Build

```bash
./build.sh
```

Compiles all sources, runs the JUnit 5 suite (fails loudly on any failure),
packages `build/vulnlens.jar`, and regenerates `docs/sample-report.html`.

## Run

```bash
# scan a pom (writes vulnlens-report.html in cwd)
java -jar build/vulnlens.jar path/to/pom.xml

# or a whole project directory (uses <dir>/pom.xml)
java -jar build/vulnlens.jar ~/projects/my-service

# machine-readable output
java -jar build/vulnlens.jar pom.xml --format json --output report.json
java -jar build/vulnlens.jar pom.xml --format text --output - --no-color

# CI gate: exit 1 if anything at/above HIGH is found
java -jar build/vulnlens.jar pom.xml --fail-on high
```

### Example

`examples/vulnerable-sample/pom.xml` pins six genuinely vulnerable-era
dependencies. Real output (trimmed):

```
VulnLens — vulnerable-sample  (6 deps, OSV.dev)
Risk score: 100/100  grade: Critical
  11×25 + 3×10 + 1×4 + 0×1 = 309 → capped at 100

DEPENDENCY                                     VERSION          SEVERITY       CVE / FIX
----------------------------------------------------------------------------------------------------
com.fasterxml.jackson.core:jackson-databind    2.9.9            critical  9.8  CVE-2019-14379  → fix: 2.9.10.4
                                                                critical  9.8  CVE-2020-8840
                                                                high      7.5  CVE-2019-14439
org.apache.logging.log4j:log4j-core            2.14.1           critical 10.0  CVE-2021-44228  → fix: 2.17.1
                                                                critical  9.0  CVE-2021-45046
                                                                high      8.6  CVE-2021-45105
                                                                medium    6.6  CVE-2021-44832
org.apache.struts:struts2-core                 2.3.24           critical 10.0  CVE-2017-5638   → fix: 2.3.35
...
15 vulnerabilities in 6/6 dependencies. Full details: re-run with --format html.
```

A full interactive HTML report for that scan ships at
[`docs/sample-report.html`](docs/sample-report.html) — risk gauge, severity
heatmap, sortable CVE table, per-dependency details.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | scan completed (report written) |
| 1 | `--fail-on <level>` threshold hit — something at/above that severity found |
| 2 | bad input (missing/malformed pom, bad flags) |
| 3 | OSV.dev unreachable (network down, API issues) |

## How it works

1. **Parse** — the pom is read with `javax.xml` DOM (XXE-hardened):
   `<dependencies>` with `${…}` placeholders resolved from `<properties>`,
   version overrides honoured from `<dependencyManagement>`, unresolvable
   versions skipped with a warning, duplicate coordinates deduped.
2. **Query** — dependencies are sent to `POST /v1/querybatch` in batches of
   50 with a descriptive `User-Agent` (standard `https_proxy` env honored).
3. **Map** — each OSV record becomes a finding: CVE alias preferred over the
   OSV id, severity from the best CVSS entry (numeric, v3.x vector computed
   per the FIRST spec, v4.0 vector via a port of FIRST's official calculator),
   fixed versions from `affected[].ranges[].events[]`.
4. **Score & suggest** — risk score = 25×critical + 10×high + 4×medium +
   1×low, capped at 100 (grades: 0–19 Low, 20–39 Moderate, 40–69 High,
   70+ Critical). Each dependency's suggested fix is the smallest fixed
   version above the current one, maximised across its vulns so one upgrade
   fixes everything — staying on the nearest release line (2.3.24 → 2.3.35,
   not 2.5.17).
5. **Report** — self-contained HTML (no external assets), JSON, or terminal
   text.

## Limitations

- **Maven only.** Gradle, npm, PyPI, Go modules are not parsed (OSV.dev
  supports them; the pom parser is the limit).
- **Needs network** at scan time — there is no offline mode; an unreachable
  API is a clean exit-3 error, not a guess.
- Only *direct* declared dependencies are scanned (no transitive resolution).
- Severity "unknown" findings are listed but contribute nothing to the score.
- Fix suggestions come from OSV range data; always verify against the
  project's own test suite before upgrading.

## Project layout

```
src/main/java/dev/vulnlens/   # the app (zero dependencies)
  VulnLens.java               # CLI entry (exit-code contract above)
  cli/                        # argument parsing
  model/                      # Dependency, VulnRecord, Severity, ScanResult
  parse/                      # hand-rolled JSON parser, pom parser, Maven version ordering
  osv/                        # OSV.dev HTTP client, record mapper, CVSS v3/v4 scoring
  scan/                       # risk score + scan orchestration
  report/                     # HTML / JSON / text renderers
  util/                       # ANSI colors
src/test/                     # JUnit 5 suite (98 tests, incl. real OSV.dev fixtures)
src/buildtools/               # sample-report generator (not shipped in the jar)
tools/osv-fixture/            # real OSV.dev records backing the sample report
examples/vulnerable-sample/   # demo pom with verified-vulnerable versions
docs/                         # GitHub Pages site (landing page + sample report)
```
