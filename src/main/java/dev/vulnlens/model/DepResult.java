package dev.vulnlens.model;

import java.util.List;

/**
 * Scan outcome for a single dependency: the dependency plus its vulnerabilities
 * (sorted worst-first) and the suggested upgrade version, if any.
 */
public record DepResult(Dependency dependency, List<VulnRecord> vulns, String suggestedFix) {

    public boolean vulnerable() {
        return !vulns.isEmpty();
    }

    public long countAtLeast(Severity floor) {
        return vulns.stream().filter(v -> v.severity().atLeast(floor)).count();
    }
}
