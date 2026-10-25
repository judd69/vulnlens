package dev.vulnlens.report;

import dev.vulnlens.model.DepResult;
import dev.vulnlens.model.ScanResult;
import dev.vulnlens.model.Severity;
import dev.vulnlens.model.VulnRecord;

/**
 * Structured JSON rendering of a {@link ScanResult} (hand-rolled, no library).
 */
public final class JsonReport {

    private JsonReport() {}

    public static String render(ScanResult r) {
        StringBuilder j = new StringBuilder();
        j.append("{\n");
        kv(j, "project", r.projectName(), 1, true);
        kv(j, "scanned_at", r.scannedAt(), 1, true);
        j.append(ind(1)).append("\"query_millis\": ").append(r.queryMillis()).append(",\n");
        j.append(ind(1)).append("\"risk_score\": ").append(r.riskScore()).append(",\n");
        kv(j, "grade", r.grade(), 1, true);
        j.append(ind(1)).append("\"summary\": {\n");
        j.append(ind(2)).append("\"dependencies_scanned\": ").append(r.dependencies().size()).append(",\n");
        j.append(ind(2)).append("\"vulnerable_dependencies\": ").append(r.vulnerableDeps()).append(",\n");
        j.append(ind(2)).append("\"total_vulnerabilities\": ").append(r.totalVulns()).append(",\n");
        j.append(ind(2)).append("\"by_severity\": {");
        boolean first = true;
        for (Severity s : Severity.values()) {
            if (!first) j.append(", ");
            j.append("\"").append(s.label()).append("\": ")
                    .append(r.severityCounts().getOrDefault(s, 0L));
            first = false;
        }
        j.append("}\n").append(ind(1)).append("},\n");
        j.append(ind(1)).append("\"dependencies\": [\n");
        for (int i = 0; i < r.dependencies().size(); i++) {
            DepResult d = r.dependencies().get(i);
            j.append(ind(2)).append("{\n");
            kv(j, "group_id", d.dependency().groupId(), 3, true);
            kv(j, "artifact_id", d.dependency().artifactId(), 3, true);
            kv(j, "version", d.dependency().version(), 3, true);
            kv(j, "scope", d.dependency().effectiveScope(), 3, true);
            if (d.suggestedFix() != null) kv(j, "suggested_fix", d.suggestedFix(), 3, true);
            else j.append(ind(3)).append("\"suggested_fix\": null,\n");
            j.append(ind(3)).append("\"vulnerabilities\": [");
            if (d.vulns().isEmpty()) {
                j.append("]");
            } else {
                j.append("\n");
                for (int k = 0; k < d.vulns().size(); k++) {
                    VulnRecord v = d.vulns().get(k);
                    j.append(ind(4)).append("{\n");
                    kv(j, "id", v.displayId(), 5, true);
                    kv(j, "osv_id", v.osvId(), 5, true);
                    kv(j, "summary", v.summary(), 5, true);
                    kv(j, "severity", v.severity().label(), 5, true);
                    if (v.cvss() != null) j.append(ind(5)).append("\"cvss\": ").append(v.scoreText()).append(",\n");
                    else j.append(ind(5)).append("\"cvss\": null,\n");
                    j.append(ind(5)).append("\"fixed_versions\": [");
                    for (int f = 0; f < v.fixedVersions().size(); f++) {
                        if (f > 0) j.append(", ");
                        j.append(quote(v.fixedVersions().get(f)));
                    }
                    j.append("],\n");
                    j.append(ind(5)).append("\"url\": ").append(quote(v.url())).append("\n");
                    j.append(ind(4)).append(k < d.vulns().size() - 1 ? "}," : "}").append("\n");
                }
                j.append(ind(3)).append("]");
            }
            j.append("\n").append(ind(2)).append(i < r.dependencies().size() - 1 ? "}," : "}").append("\n");
        }
        j.append(ind(1)).append("]\n}\n");
        return j.toString();
    }

    private static void kv(StringBuilder j, String key, String value, int indent, boolean comma) {
        j.append(ind(indent)).append("\"").append(key).append("\": ").append(quote(value));
        if (comma) j.append(",");
        j.append("\n");
    }

    private static String ind(int n) {
        return "  ".repeat(n);
    }

    static String quote(String s) {
        if (s == null) return "null";
        StringBuilder o = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> o.append("\\\"");
                case '\\' -> o.append("\\\\");
                case '\n' -> o.append("\\n");
                case '\r' -> o.append("\\r");
                case '\t' -> o.append("\\t");
                default -> {
                    if (c < 0x20) o.append(String.format("\\u%04x", (int) c));
                    else o.append(c);
                }
            }
        }
        return o.append("\"").toString();
    }
}
