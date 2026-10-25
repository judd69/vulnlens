package dev.vulnlens.report;

import dev.vulnlens.model.DepResult;
import dev.vulnlens.model.ScanResult;
import dev.vulnlens.model.Severity;
import dev.vulnlens.model.VulnRecord;
import dev.vulnlens.scan.RiskScore;
import dev.vulnlens.util.Ansi;

/**
 * Compact terminal rendering: risk score line, per-dependency CVE table,
 * fix suggestions. Colors unless disabled.
 */
public final class TextReport {

    private TextReport() {}

    public static String render(ScanResult r, boolean color) {
        Ansi ansi = new Ansi(color);
        StringBuilder t = new StringBuilder();
        t.append(ansi.bold("VulnLens")).append(" — ").append(r.projectName())
                .append("  (").append(r.dependencies().size()).append(" deps, OSV.dev)\n");

        String gradeColor = switch (r.grade()) {
            case "Critical" -> ansi.red();
            case "High" -> ansi.yellow();
            case "Moderate" -> ansi.cyan();
            default -> ansi.green();
        };
        t.append("Risk score: ").append(gradeColor).append(ansi.bold(r.riskScore() + "/100"))
                .append(ansi.reset()).append("  grade: ").append(gradeColor).append(r.grade())
                .append(ansi.reset()).append("\n");
        t.append(ansi.dim("  " + RiskScore.explain(RiskScore.compute(r.severityCounts())))).append("\n\n");

        t.append(String.format("%-46s %-16s %-14s %s\n", "DEPENDENCY", "VERSION", "SEVERITY", "CVE / FIX"));
        t.append("-".repeat(100)).append("\n");
        for (DepResult d : r.dependencies()) {
            String dep = d.dependency().coordinate();
            if (dep.length() > 45) dep = dep.substring(0, 44) + "…";
            if (d.vulns().isEmpty()) {
                t.append(String.format("%-46s %-16s %s\n", dep, d.dependency().version(),
                        ansi.green() + "clean" + ansi.reset()));
                continue;
            }
            boolean first = true;
            for (VulnRecord v : d.vulns()) {
                String sevColor = switch (v.severity()) {
                    case CRITICAL -> ansi.red();
                    case HIGH -> ansi.yellow();
                    case MEDIUM -> ansi.cyan();
                    case LOW -> ansi.green();
                    case UNKNOWN -> ansi.dim("");
                };
                String sev = sevColor + String.format("%-8s %4s", v.severity().label(), v.scoreText()) + ansi.reset();
                String fix = d.suggestedFix() != null ? "  → fix: " + d.suggestedFix() : "";
                t.append(String.format("%-46s %-16s %-14s %s%s\n",
                        first ? dep : "", first ? d.dependency().version() : "",
                        sev, v.displayId(), first ? fix : ""));
                first = false;
            }
        }
        t.append("\n").append(r.totalVulns()).append(" vulnerabilities in ")
                .append(r.vulnerableDeps()).append("/").append(r.dependencies().size())
                .append(" dependencies. Full details: re-run with --format html.\n");
        return t.toString();
    }
}
