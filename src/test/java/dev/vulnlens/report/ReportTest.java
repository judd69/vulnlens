package dev.vulnlens.report;

import dev.vulnlens.model.DepResult;
import dev.vulnlens.model.Dependency;
import dev.vulnlens.model.ScanResult;
import dev.vulnlens.model.Severity;
import dev.vulnlens.model.VulnRecord;
import dev.vulnlens.parse.Json;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ReportTest {

    private static ScanResult sample() {
        Dependency d = new Dependency("org.apache.logging.log4j", "log4j-core", "2.14.1", "", "");
        VulnRecord v = new VulnRecord("GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228",
                "Log4Shell <script>alert(1)</script> & friends", 10.0, Severity.CRITICAL,
                List.of("2.15.0"), "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q");
        DepResult dr = new DepResult(d, List.of(v), "2.15.0");
        Map<Severity, Long> counts = new java.util.EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) counts.put(s, 0L);
        counts.put(Severity.CRITICAL, 1L);
        return ScanResult.assemble("demo", "2026-10-24T00:00:00Z", 42, List.of(dr), 25, "Moderate");
    }

    @Test
    void htmlContainsScoreCveAndLinks() {
        String html = HtmlReport.render(sample());
        assertTrue(html.contains("25"), "risk score present");
        assertTrue(html.contains("CVE-2021-44228"));
        assertTrue(html.contains("https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q"));
        assertTrue(html.contains("heatmap"), "heatmap section present");
        assertTrue(html.contains("2.15.0"), "fix suggestion present");
    }

    @Test
    void htmlEscapesUntrustedContent() {
        String html = HtmlReport.render(sample());
        assertFalse(html.contains("<script>alert(1)</script>"), "raw script must not appear");
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assertTrue(html.contains("&amp; friends"));
    }

    @Test
    void htmlHasNoExternalAssets() {
        String html = HtmlReport.render(sample());
        assertFalse(html.contains("src=\"http"), "no external scripts");
        assertFalse(html.contains("href=\"http") && html.contains("stylesheet"), "no external stylesheets");
        assertFalse(html.contains("fonts.googleapis.com"));
        assertTrue(html.contains("<style>") && html.contains("<script>"), "assets are inline");
    }

    @Test
    void jsonIsWellFormed() {
        String json = JsonReport.render(sample());
        Json.JObject o = (Json.JObject) Json.parse(json);
        assertEquals("demo", o.str("project"));
        assertEquals("25", o.get("risk_score") instanceof Json.JNumber n ? n.raw() : null);
        assertEquals("Moderate", o.str("grade"));
        Json.JArray deps = o.arr("dependencies");
        assertEquals(1, deps.size());
        Json.JObject dep = (Json.JObject) deps.get(0);
        assertEquals("CVE-2021-44228",
                ((Json.JObject) dep.arr("vulnerabilities").get(0)).str("id"));
        assertEquals("2.15.0", dep.str("suggested_fix"));
    }

    @Test
    void textRendersTableAndScore() {
        String text = TextReport.render(sample(), false);
        assertTrue(text.contains("25/100"));
        assertTrue(text.contains("CVE-2021-44228"));
        assertTrue(text.contains("log4j-core"));
        assertFalse(text.contains("\u001B["), "no ANSI escapes when color disabled");
    }

    @Test
    void textUsesColorWhenEnabled() {
        String text = TextReport.render(sample(), true);
        assertTrue(text.contains("\u001B["), "ANSI escapes present when color enabled");
    }
}
