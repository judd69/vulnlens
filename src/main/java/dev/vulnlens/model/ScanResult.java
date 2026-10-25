package dev.vulnlens.model;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * The complete outcome of scanning one Maven project.
 */
public record ScanResult(
        String projectName,
        String scannedAt,
        long queryMillis,
        List<DepResult> dependencies,
        int riskScore,
        String grade,
        Map<Severity, Long> severityCounts,
        long totalVulns) {

    public static ScanResult assemble(String projectName, String scannedAt, long queryMillis,
                                      List<DepResult> dependencies, int riskScore, String grade) {
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) counts.put(s, 0L);
        long total = 0;
        for (DepResult d : dependencies) {
            for (VulnRecord v : d.vulns()) {
                counts.merge(v.severity(), 1L, Long::sum);
                total++;
            }
        }
        return new ScanResult(projectName, scannedAt, queryMillis,
                List.copyOf(dependencies), riskScore, grade, counts, total);
    }

    public long vulnerableDeps() {
        return dependencies.stream().filter(DepResult::vulnerable).count();
    }
}
