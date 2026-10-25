package dev.vulnlens.parse;

import dev.vulnlens.model.Dependency;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PomParserTest {

    @TempDir Path tmp;

    private Path writePom(String name, String body) throws Exception {
        Path p = tmp.resolve(name);
        Files.writeString(p, body, StandardCharsets.UTF_8);
        return p;
    }

    private static final String BASIC = """
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
                <dependency>
                  <groupId>junit</groupId>
                  <artifactId>junit</artifactId>
                  <version>4.13.2</version>
                  <scope>test</scope>
                </dependency>
              </dependencies>
            </project>
            """;

    @Test
    void parsesBasicDependencies() throws Exception {
        var r = PomParser.parse(writePom("pom.xml", BASIC));
        assertEquals(2, r.dependencies().size());
        Dependency d = r.dependencies().get(0);
        assertEquals("org.apache.logging.log4j", d.groupId());
        assertEquals("log4j-core", d.artifactId());
        assertEquals("2.14.1", d.version());
        assertEquals("test", r.dependencies().get(1).scope());
    }

    @Test
    void resolvesPropertyPlaceholders() throws Exception {
        String pom = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <properties><log4j.version>2.14.1</log4j.version></properties>
                  <dependencies>
                    <dependency>
                      <groupId>org.apache.logging.log4j</groupId>
                      <artifactId>log4j-core</artifactId>
                      <version>${log4j.version}</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
        var r = PomParser.parse(writePom("pom.xml", pom));
        assertEquals(1, r.dependencies().size());
        assertEquals("2.14.1", r.dependencies().get(0).version());
    }

    @Test
    void honorsDependencyManagement() throws Exception {
        String pom = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.fasterxml.jackson.core</groupId>
                        <artifactId>jackson-databind</artifactId>
                        <version>2.9.9</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                  <dependencies>
                    <dependency>
                      <groupId>com.fasterxml.jackson.core</groupId>
                      <artifactId>jackson-databind</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """;
        var r = PomParser.parse(writePom("pom.xml", pom));
        assertEquals(1, r.dependencies().size());
        assertEquals("2.9.9", r.dependencies().get(0).version());
        assertTrue(r.dependencies().get(0).note().contains("dependencyManagement"));
    }

    @Test
    void skipsUnresolvableVersionWithWarning() throws Exception {
        String pom = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>mystery</artifactId>
                      <version>${nope.version}</version>
                    </dependency>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>noversion</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """;
        var r = PomParser.parse(writePom("pom.xml", pom));
        assertTrue(r.dependencies().isEmpty());
        assertEquals(2, r.warnings().size());
    }

    @Test
    void dedupesIdenticalCoordinates() throws Exception {
        String pom = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <dependencies>
                    <dependency>
                      <groupId>a</groupId><artifactId>b</artifactId><version>1.0</version>
                    </dependency>
                    <dependency>
                      <groupId>a</groupId><artifactId>b</artifactId><version>2.0</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
        var r = PomParser.parse(writePom("pom.xml", pom));
        assertEquals(1, r.dependencies().size());
        assertEquals("1.0", r.dependencies().get(0).version());
        assertEquals(1, r.warnings().size());
    }

    @Test
    void rejectsMalformedXml() throws Exception {
        Path p = writePom("pom.xml", "<project><oops>");
        assertThrows(PomParser.PomException.class, () -> PomParser.parse(p));
    }

    @Test
    void rejectsMissingFile() {
        assertThrows(PomParser.PomException.class,
                () -> PomParser.parse(tmp.resolve("nope.xml")));
    }

    @Test
    void resolvePomInputAcceptsDirectory() throws Exception {
        Path dir = tmp.resolve("proj");
        Files.createDirectory(dir);
        writePom("proj/pom.xml", BASIC);
        assertEquals(dir.resolve("pom.xml"), PomParser.resolvePomInput(dir));
    }

    @Test
    void resolvePomInputRejectsDirectoryWithoutPom() throws Exception {
        Path dir = tmp.resolve("empty");
        Files.createDirectory(dir);
        assertThrows(PomParser.PomException.class, () -> PomParser.resolvePomInput(dir));
    }

    @Test
    void placeholderResolutionIsCycleSafe() {
        Map<String, String> props = Map.of("a", "${b}", "b", "${a}");
        String out = PomParser.resolve("${a}", props);
        assertTrue(out.contains("${"), "cycle should leave placeholder unresolved, got: " + out);
    }
}
