package dev.vulnlens.scan;

import dev.vulnlens.model.DepResult;
import dev.vulnlens.model.Dependency;
import dev.vulnlens.model.ScanResult;
import dev.vulnlens.model.Severity;
import dev.vulnlens.model.VulnRecord;
import dev.vulnlens.osv.OsvMapper;
import dev.vulnlens.osv.VulnerabilitySource;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Orchestrates a scan: queries the vulnerability source for every dependency,
 * sorts findings worst-first, computes fix suggestions and the risk score.
 */
public final class ScanEngine {

    private ScanEngine() {}

    public static ScanResult scan(String projectName, List<Dependency> deps, VulnerabilitySource source)
            throws VulnerabilitySource.OsvException {
        List<List<VulnRecord>> perDep = source.query(deps);
        return assemble(projectName, deps, perDep, source.lastQueryMillis());
    }

    /** Pure assembly from already-fetched vuln lists (also used by build tooling). */
    public static ScanResult assemble(String projectName, List<Dependency> deps,
                                      List<List<VulnRecord>> perDep, long queryMillis) {
        List<DepResult> results = new ArrayList<>();
        for (int i = 0; i < deps.size(); i++) {
            List<VulnRecord> vulns = i < perDep.size() ? new ArrayList<>(perDep.get(i)) : new ArrayList<>();
            vulns.sort(Comparator
                    .comparing((VulnRecord v) -> v.severity().ordinal())
                    .thenComparing(v -> v.cvss() == null ? -1 : v.cvss(), Comparator.reverseOrder())
                    .thenComparing(VulnRecord::displayId));
            results.add(new DepResult(deps.get(i), List.copyOf(vulns),
                    OsvMapper.suggestedFix(vulns, deps.get(i).version())));
        }
        // worst dependencies first: most criticals, then most vulns, then name
        results.sort((a, b) -> {
            int c = Long.compare(b.countAtLeast(Severity.CRITICAL), a.countAtLeast(Severity.CRITICAL));
            if (c != 0) return c;
            c = Integer.compare(b.vulns().size(), a.vulns().size());
            if (c != 0) return c;
            return a.dependency().coordinate().compareTo(b.dependency().coordinate());
        });

        String now = DateTimeFormatter.ISO_OFFSET_DATE_TIME.withZone(ZoneOffset.UTC).format(Instant.now());
        java.util.Map<Severity, Long> counts = new java.util.EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) counts.put(s, 0L);
        for (DepResult d : results) {
            for (VulnRecord v : d.vulns()) counts.merge(v.severity(), 1L, Long::sum);
        }
        RiskScore.Breakdown b = RiskScore.compute(counts);
        return ScanResult.assemble(projectName, now, queryMillis, results, b.score(), b.grade());
    }

    /** True when any finding is at or above the fail-on floor (for --fail-on). */
    public static boolean meetsFailOn(ScanResult result, Severity floor) {
        return result.dependencies().stream()
                .flatMap(d -> d.vulns().stream())
                .anyMatch(v -> v.severity().atLeast(floor));
    }
}
