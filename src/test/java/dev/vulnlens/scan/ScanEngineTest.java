package dev.vulnlens.scan;

import dev.vulnlens.model.Dependency;
import dev.vulnlens.model.ScanResult;
import dev.vulnlens.model.Severity;
import dev.vulnlens.model.VulnRecord;
import dev.vulnlens.osv.VulnerabilitySource;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScanEngineTest {

    private static Dependency dep(String g, String a, String v) {
        return new Dependency(g, a, v, "", "");
    }

    private static VulnRecord vuln(String id, Double cvss) {
        return new VulnRecord("OSV-" + id, id, "summary " + id, cvss,
                Severity.of(cvss), cvss != null ? List.of("9.9") : List.of(), "https://osv.dev/x");
    }

    private static VulnerabilitySource stub(List<List<VulnRecord>> data, long millis) {
        return new VulnerabilitySource() {
            @Override
            public List<List<VulnRecord>> query(List<Dependency> deps) { return data; }
            @Override
            public long lastQueryMillis() { return millis; }
        };
    }

    @Test
    void assemblesScoresAndSortsWorstFirst() throws Exception {
        List<Dependency> deps = List.of(dep("a", "clean", "1.0"), dep("b", "bad", "2.0"));
        var result = ScanEngine.scan("proj", deps,
                stub(List.of(List.of(), List.of(vuln("CVE-1", 9.8), vuln("CVE-2", 4.5))), 123));
        assertEquals(2, result.dependencies().size());
        assertEquals("b:bad", result.dependencies().get(0).dependency().coordinate(),
                "most vulnerable dependency first");
        assertEquals("CVE-1", result.dependencies().get(0).vulns().get(0).displayId(),
                "vulns sorted worst-first");
        assertEquals(2, result.totalVulns());
        assertEquals(1, result.vulnerableDeps());
        assertEquals(123, result.queryMillis());
        // 1 critical (25) + 1 medium (4) = 29 -> Moderate
        assertEquals(29, result.riskScore());
        assertEquals("Moderate", result.grade());
        assertEquals("9.9", result.dependencies().get(0).suggestedFix());
    }

    @Test
    void emptyVulnsScoresZero() throws Exception {
        var result = ScanEngine.scan("proj", List.of(dep("a", "b", "1.0")),
                stub(List.of(List.of()), 0));
        assertEquals(0, result.riskScore());
        assertEquals("Low", result.grade());
        assertEquals(0, result.totalVulns());
    }

    @Test
    void failOnTriggersAtThreshold() throws Exception {
        var result = ScanEngine.scan("proj", List.of(dep("a", "b", "1.0")),
                stub(List.of(List.of(vuln("CVE-1", 7.5))), 0));
        assertTrue(ScanEngine.meetsFailOn(result, Severity.MEDIUM));
        assertTrue(ScanEngine.meetsFailOn(result, Severity.HIGH));
        assertFalse(ScanEngine.meetsFailOn(result, Severity.CRITICAL));
    }

    @Test
    void failOnIgnoresUnknownSeverity() throws Exception {
        var result = ScanEngine.scan("proj", List.of(dep("a", "b", "1.0")),
                stub(List.of(List.of(vuln("CVE-1", null))), 0));
        assertFalse(ScanEngine.meetsFailOn(result, Severity.LOW));
    }
}
