package dev.vulnlens.osv;

import dev.vulnlens.model.Dependency;
import dev.vulnlens.model.Severity;
import dev.vulnlens.model.VulnRecord;
import dev.vulnlens.parse.Json;
import dev.vulnlens.parse.MavenVersion;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Maps raw OSV.dev JSON records to {@link VulnRecord}s.
 * <ul>
 *   <li>display id: a CVE alias when present, else the OSV id;</li>
 *   <li>severity: best CVSS score across {@code severity[]} entries
 *       (numeric strings, CVSS v3.x vectors, CVSS v4.0 vectors);</li>
 *   <li>fixed versions: {@code fixed} events from ECOSYSTEM/SEMVER ranges,
 *       falling back to fixed versions in CPE-derived range metadata;</li>
 *   <li>only ranges matching the queried Maven coordinate contribute fixes.</li>
 * </ul>
 */
public final class OsvMapper {

    private OsvMapper() {}

    private static final Pattern COMMIT_HASH = Pattern.compile("^[0-9a-f]{40}$");
    private static final Pattern VERSION_LIKE = Pattern.compile("^[0-9A-Za-z][0-9A-Za-z.\\-+_]*$");

    /** Parse one {@code {"results":[...]}} batch response into per-query vuln lists. */
    public static List<List<VulnRecord>> parseBatch(String body, List<Dependency> queries) {
        Json.Value root = Json.parse(body);
        if (!(root instanceof Json.JObject o)) throw new IllegalArgumentException("batch response is not an object");
        Json.JArray results = o.arr("results");
        if (results == null) throw new IllegalArgumentException("batch response has no 'results'");
        List<List<VulnRecord>> out = new ArrayList<>();
        for (int i = 0; i < results.size(); i++) {
            List<VulnRecord> vulns = new ArrayList<>();
            Dependency dep = i < queries.size() ? queries.get(i) : null;
            Json.Value r = results.get(i);
            if (r instanceof Json.JObject ro) {
                Json.JArray va = ro.arr("vulns");
                if (va != null) {
                    for (int k = 0; k < va.size(); k++) {
                        if (va.get(k) instanceof Json.JObject vo) {
                            vulns.add(mapRecord(vo, dep));
                        }
                    }
                }
            }
            out.add(vulns);
        }
        return out;
    }

    /** Map a single OSV vulnerability record object. Package-private for tests. */
    static VulnRecord mapRecord(Json.JObject v, Dependency dep) {
        String osvId = v.str("id", "");
        String displayId = osvId;
        Json.JArray aliases = v.arr("aliases");
        if (aliases != null) {
            for (int i = 0; i < aliases.size(); i++) {
                if (aliases.get(i) instanceof Json.JString s && s.value().startsWith("CVE-")) {
                    displayId = s.value();
                    break;
                }
            }
        }
        String summary = v.str("summary", "");
        if (summary.isBlank()) summary = v.str("details", "");
        if (summary.length() > 220) summary = summary.substring(0, 217) + "...";

        Double best = null;
        Json.JArray severity = v.arr("severity");
        if (severity != null) {
            for (int i = 0; i < severity.size(); i++) {
                if (severity.get(i) instanceof Json.JObject s) {
                    Double d = Cvss.score(s.str("type"), s.str("score"));
                    if (d != null && !d.isNaN() && (best == null || d > best)) best = d;
                }
            }
        }

        Set<String> fixed = new LinkedHashSet<>();
        Json.JArray affected = v.arr("affected");
        if (affected != null) {
            for (int i = 0; i < affected.size(); i++) {
                if (!(affected.get(i) instanceof Json.JObject a)) continue;
                if (dep != null && !packageMatches(a, dep)) continue;
                collectFixed(a, fixed);
            }
        }
        // fall back to the whole record when no affected entry matched the package
        if (fixed.isEmpty() && affected != null) {
            for (int i = 0; i < affected.size(); i++) {
                if (affected.get(i) instanceof Json.JObject a) collectFixed(a, fixed);
            }
        }

        return new VulnRecord(osvId, displayId, summary, best, Severity.of(best),
                List.copyOf(fixed), "https://osv.dev/vulnerability/" + osvId);
    }

    private static boolean packageMatches(Json.JObject affected, Dependency dep) {
        Json.JObject pkg = affected.obj("package");
        if (pkg == null) return false;
        String name = pkg.str("name");
        String eco = pkg.str("ecosystem");
        return dep.coordinate().equals(name) && "Maven".equalsIgnoreCase(eco);
    }

    private static void collectFixed(Json.JObject affected, Set<String> fixed) {
        Json.JArray ranges = affected.arr("ranges");
        if (ranges == null) return;
        for (int i = 0; i < ranges.size(); i++) {
            if (!(ranges.get(i) instanceof Json.JObject r)) continue;
            String type = r.str("type", "");
            Json.JArray events = r.arr("events");
            if (events == null) continue;
            for (int k = 0; k < events.size(); k++) {
                if (!(events.get(k) instanceof Json.JObject e)) continue;
                String f = e.str("fixed");
                if (f == null) continue;
                if (COMMIT_HASH.matcher(f).matches()) continue; // git sha, not a version
                if (("ECOSYSTEM".equals(type) || "SEMVER".equals(type)) && VERSION_LIKE.matcher(f).matches()) {
                    fixed.add(f);
                }
            }
            // CPE-derived metadata (NVD-sourced records): extracted version ranges
            Json.JObject db = r.obj("database_specific");
            if (db != null) {
                Json.JArray extracted = db.arr("extracted_events");
                if (extracted != null) {
                    for (int k = 0; k < extracted.size(); k++) {
                        if (!(extracted.get(k) instanceof Json.JObject x)) continue;
                        Json.JArray range = x.arr("range");
                        if (range == null) continue;
                        for (int j = 0; j < range.size(); j++) {
                            if (range.get(j) instanceof Json.JObject re) {
                                String f = re.str("fixed");
                                if (f != null && VERSION_LIKE.matcher(f).matches()
                                        && !COMMIT_HASH.matcher(f).matches()) {
                                    fixed.add(f);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Suggested upgrade version: for each vuln, take its smallest fixed version
     * above the current one (staying on the nearest release line), then take the
     * maximum across vulns so the suggestion fixes everything. Null when no safe
     * suggestion can be derived.
     */
    public static String suggestedFix(List<VulnRecord> vulns, String currentVersion) {
        MavenVersion current = MavenVersion.of(currentVersion);
        List<String> perVulnMin = new ArrayList<>();
        for (VulnRecord v : vulns) {
            String best = null;
            MavenVersion bestMv = null;
            for (String f : v.fixedVersions()) {
                MavenVersion fm = MavenVersion.of(f);
                if (fm.compareTo(current) > 0 && (bestMv == null || fm.compareTo(bestMv) < 0)) {
                    bestMv = fm;
                    best = f;
                }
            }
            if (best == null) return null; // this vuln has no usable fix above current
            perVulnMin.add(best);
        }
        return MavenVersion.maxOf(perVulnMin);
    }
}
