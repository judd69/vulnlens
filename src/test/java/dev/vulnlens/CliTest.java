package dev.vulnlens;

import dev.vulnlens.model.Dependency;
import dev.vulnlens.model.Severity;
import dev.vulnlens.model.VulnRecord;
import dev.vulnlens.osv.VulnerabilitySource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end CLI tests with a stubbed vulnerability source (no network).
 * Exit codes: 0 ok · 1 --fail-on hit · 2 bad input · 3 source unreachable.
 */
class CliTest {

    @TempDir Path tmp;

    @AfterEach
    void clearOverride() {
        VulnLens.sourceOverride = null;
    }

    private Path pom(String body) throws Exception {
        Path p = tmp.resolve("pom.xml");
        Files.writeString(p, body, StandardCharsets.UTF_8);
        return p;
    }

    private static final String POM = """
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>demo</artifactId>
              <version>1.0</version>
              <dependencies>
                <dependency>
                  <groupId>org.apache.logging.log4j</groupId>
                  <artifactId>log4j-core</artifactId>
                  <version>2.14.1</version>
                </dependency>
              </dependencies>
            </project>
            """;

    private static VulnerabilitySource stub(List<VulnRecord> vulns) {
        return deps -> deps.stream().map(d -> vulns).toList();
    }

    private static VulnRecord crit() {
        return new VulnRecord("GHSA-x", "CVE-2021-44228", "s", 10.0,
                Severity.CRITICAL, List.of("2.15.0"), "https://osv.dev/vulnerability/GHSA-x");
    }

    @Test
    void helpExitsZero() {
        assertEquals(0, VulnLens.run(new String[]{"--help"}));
    }

    @Test
    void malformedPomExitsTwo() throws Exception {
        Path p = pom("<project><broken>");
        assertEquals(2, VulnLens.run(new String[]{p.toString(), "--format", "text"}));
    }

    @Test
    void missingInputExitsTwo() {
        assertEquals(2, VulnLens.run(new String[]{tmp.resolve("nope.xml").toString()}));
    }

    @Test
    void noInputExitsTwo() {
        assertEquals(2, VulnLens.run(new String[]{}));
    }

    @Test
    void unknownFlagExitsTwo() throws Exception {
        Path p = pom(POM);
        assertEquals(2, VulnLens.run(new String[]{p.toString(), "--bogus"}));
    }

    @Test
    void failOnHighWithCriticalExitsOne() throws Exception {
        Path p = pom(POM);
        VulnLens.sourceOverride = stub(List.of(crit()));
        Path out = tmp.resolve("r.html");
        assertEquals(1, VulnLens.run(new String[]{p.toString(), "--fail-on", "high",
                "--output", out.toString(), "--quiet"}));
        assertTrue(Files.exists(out));
    }

    @Test
    void cleanScanExitsZeroAndWritesJson() throws Exception {
        Path p = pom(POM);
        VulnLens.sourceOverride = stub(List.of());
        Path out = tmp.resolve("r.json");
        assertEquals(0, VulnLens.run(new String[]{p.toString(), "--format", "json",
                "--output", out.toString(), "--quiet", "--fail-on", "low"}));
        String json = Files.readString(out);
        assertTrue(json.contains("\"risk_score\": 0"));
        assertTrue(json.contains("\"grade\": \"Low\""));
    }

    @Test
    void textToStdout() throws Exception {
        Path p = pom(POM);
        VulnLens.sourceOverride = stub(List.of(crit()));
        assertEquals(0, VulnLens.run(new String[]{p.toString(), "--format", "text",
                "--output", "-", "--no-color", "--quiet"}));
    }

    @Test
    void unreachableSourceExitsThree() throws Exception {
        Path p = pom(POM);
        VulnLens.sourceOverride = deps -> {
            throw new VulnerabilitySource.OsvException("cannot reach OSV.dev (simulated)");
        };
        assertEquals(3, VulnLens.run(new String[]{p.toString(), "--format", "text", "--quiet"}));
    }

    @Test
    void directoryInputResolvesPom() throws Exception {
        Path dir = tmp.resolve("proj");
        Files.createDirectory(dir);
        Files.writeString(dir.resolve("pom.xml"), POM, StandardCharsets.UTF_8);
        VulnLens.sourceOverride = stub(List.of());
        Path out = tmp.resolve("r.txt");
        assertEquals(0, VulnLens.run(new String[]{dir.toString(), "--format", "text",
                "--output", out.toString(), "--quiet", "--no-color"}));
        assertTrue(Files.readString(out).contains("0/100"));
    }
}
