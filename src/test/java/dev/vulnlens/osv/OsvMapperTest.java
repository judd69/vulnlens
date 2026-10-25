package dev.vulnlens.osv;

import dev.vulnlens.model.Dependency;
import dev.vulnlens.model.Severity;
import dev.vulnlens.model.VulnRecord;
import dev.vulnlens.parse.Json;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Mapping tests against REAL OSV.dev records (fetched live 2026-10-24,
 * stored under src/test/resources/osv).
 */
class OsvMapperTest {

    private static Json.JObject fixture(String name) throws Exception {
        // test resources are copied next to test classes by build.sh
        var url = OsvMapperTest.class.getResource("/osv/" + name);
        assertNotNull(url, "fixture missing: " + name);
        String body = Files.readString(Path.of(url.toURI()), StandardCharsets.UTF_8);
        return (Json.JObject) Json.parse(body);
    }

    private static Dependency dep(String g, String a, String v) {
        return new Dependency(g, a, v, "", "");
    }

    @Test
    void mapsLog4ShellRecord() throws Exception {
        VulnRecord r = OsvMapper.mapRecord(fixture("GHSA-jfh8-c2jp-5v3q.json"),
                dep("org.apache.logging.log4j", "log4j-core", "2.14.1"));
        assertEquals("GHSA-jfh8-c2jp-5v3q", r.osvId());
        assertEquals("CVE-2021-44228", r.displayId(), "CVE alias preferred over OSV id");
        assertEquals(10.0, r.cvss());
        assertEquals(Severity.CRITICAL, r.severity());
        assertTrue(r.fixedVersions().contains("2.15.0"), "fixed versions: " + r.fixedVersions());
        assertEquals("https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q", r.url());
        assertFalse(r.summary().isBlank());
    }

    @Test
    void mapsText4ShellRecord() throws Exception {
        VulnRecord r = OsvMapper.mapRecord(fixture("GHSA-599f-7c49-w659.json"),
                dep("org.apache.commons", "commons-text", "1.9"));
        assertEquals("CVE-2022-42889", r.displayId());
        assertEquals(9.8, r.cvss());
        assertEquals(Severity.CRITICAL, r.severity());
        assertTrue(r.fixedVersions().contains("1.10.0"));
    }

    @Test
    void mapsStrutsRecord() throws Exception {
        VulnRecord r = OsvMapper.mapRecord(fixture("GHSA-j77q-2qqg-6989.json"),
                dep("org.apache.struts", "struts2-core", "2.3.24"));
        assertEquals("CVE-2017-5638", r.displayId());
        assertEquals(10.0, r.cvss());
        assertTrue(r.fixedVersions().contains("2.3.32"));
    }

    @Test
    void unknownSeverityWhenNoScore() throws Exception {
        Json.JObject v = (Json.JObject) Json.parse(
                "{\"id\":\"GHSA-test\",\"affected\":[],\"summary\":\"x\"}");
        VulnRecord r = OsvMapper.mapRecord(v, dep("a", "b", "1.0"));
        assertNull(r.cvss());
        assertEquals(Severity.UNKNOWN, r.severity());
        assertEquals("GHSA-test", r.displayId(), "falls back to OSV id without CVE alias");
    }

    @Test
    void parseBatchAlignsResultsToQueries() throws Exception {
        String log4j = Files.readString(
                Path.of(OsvMapperTest.class.getResource("/osv/GHSA-jfh8-c2jp-5v3q.json").toURI()));
        String batch = "{\"results\":[{\"vulns\":[" + log4j + "]},{}]}";
        List<Dependency> deps = List.of(
                dep("org.apache.logging.log4j", "log4j-core", "2.14.1"),
                dep("com.example", "clean", "1.0"));
        List<List<VulnRecord>> out = OsvMapper.parseBatch(batch, deps);
        assertEquals(2, out.size());
        assertEquals(1, out.get(0).size());
        assertEquals("CVE-2021-44228", out.get(0).get(0).displayId());
        assertTrue(out.get(1).isEmpty());
    }

    @Test
    void suggestedFixStaysOnNearestReleaseLine() {
        // struts2-core 2.3.24: fixed lines are 2.3.x and 2.5.x — must suggest 2.3.35, not 2.5.17
        List<VulnRecord> vulns = List.of(
                new VulnRecord("G1", "CVE-2017-5638", "", 10.0, Severity.CRITICAL,
                        List.of("2.3.32", "2.5.10.1"), ""),
                new VulnRecord("G2", "CVE-2018-11776", "", 8.1, Severity.HIGH,
                        List.of("2.3.35", "2.5.17"), ""));
        assertEquals("2.3.35", OsvMapper.suggestedFix(vulns, "2.3.24"));
    }

    @Test
    void suggestedFixFixesEveryVuln() {
        List<VulnRecord> vulns = List.of(
                new VulnRecord("G1", "CVE-1", "", 9.0, Severity.CRITICAL, List.of("2.15.0", "2.16.0"), ""),
                new VulnRecord("G2", "CVE-2", "", 7.5, Severity.HIGH, List.of("2.17.1"), ""));
        assertEquals("2.17.1", OsvMapper.suggestedFix(vulns, "2.14.1"));
    }

    @Test
    void suggestedFixNullWhenNoUsableFix() {
        List<VulnRecord> vulns = List.of(
                new VulnRecord("G1", "CVE-1", "", 9.0, Severity.CRITICAL, List.of(), ""));
        assertNull(OsvMapper.suggestedFix(vulns, "1.0"));
        assertNull(OsvMapper.suggestedFix(List.of(), "1.0"));
    }

    @Test
    void ignoresCommitHashFixedEvents() throws Exception {
        Json.JObject v = (Json.JObject) Json.parse("""
                {"id":"GHSA-x","aliases":[],"severity":[],
                 "affected":[{"package":{"name":"a:b","ecosystem":"Maven"},
                   "ranges":[{"type":"GIT","events":[{"fixed":"38513a7d57343881f7bf58f37e67d6a87e0a47c"}]},
                             {"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"1.2"}]}]}]}
                """);
        VulnRecord r = OsvMapper.mapRecord(v, dep("a", "b", "1.1"));
        assertEquals(List.of("1.2"), r.fixedVersions(), "git sha must not be treated as a version");
    }
}
