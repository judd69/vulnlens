package dev.vulnlens.parse;

import dev.vulnlens.model.Dependency;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses a Maven pom.xml with {@code javax.xml} DOM: extracts declared
 * dependencies with versions resolved from {@code <properties>} and honoured
 * from {@code <dependencyManagement>}. Dependencies whose version cannot be
 * resolved are skipped with a warning.
 */
public final class PomParser {

    private PomParser() {}

    public record ParseResult(List<Dependency> dependencies, List<String> warnings) {}

    public static class PomException extends Exception {
        public PomException(String message) { super(message); }
        public PomException(String message, Throwable cause) { super(message, cause); }
    }

    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]+)}");

    public static ParseResult parse(Path pomFile) throws PomException {
        Document doc = load(pomFile);

        Map<String, String> properties = new LinkedHashMap<>();
        for (Element props : directChildren(doc.getDocumentElement(), "properties")) {
            for (Element p : childElements(props)) {
                properties.put(p.getTagName(), p.getTextContent().trim());
            }
        }

        // dependencyManagement: coordinate -> version
        Map<String, String> managed = new LinkedHashMap<>();
        for (Element dm : directChildren(doc.getDocumentElement(), "dependencyManagement")) {
            for (Element deps : directChildren(dm, "dependencies")) {
                for (Element dep : directChildren(deps, "dependency")) {
                    String g = text(dep, "groupId");
                    String a = text(dep, "artifactId");
                    String v = text(dep, "version");
                    if (g != null && a != null && v != null) {
                        managed.put(g + ":" + a, resolve(v, properties));
                    }
                }
            }
        }

        List<Dependency> deps = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Map<String, Dependency> seen = new LinkedHashMap<>();

        for (Element dependencies : directChildren(doc.getDocumentElement(), "dependencies")) {
            for (Element dep : directChildren(dependencies, "dependency")) {
                String g = text(dep, "groupId");
                String a = text(dep, "artifactId");
                if (g == null || g.isBlank() || a == null || a.isBlank()) {
                    warnings.add("skipping dependency with missing groupId/artifactId");
                    continue;
                }
                g = resolve(g, properties);
                a = resolve(a, properties);
                String rawVersion = text(dep, "version");
                String version = null;
                String note = "";
                if (rawVersion != null && !rawVersion.isBlank()) {
                    version = resolve(rawVersion, properties);
                } else if (managed.containsKey(g + ":" + a)) {
                    version = managed.get(g + ":" + a);
                    note = "version from dependencyManagement";
                }
                if (version == null || version.isBlank() || PLACEHOLDER.matcher(version).find()) {
                    warnings.add("skipping " + g + ":" + a + ": version could not be resolved"
                            + (rawVersion == null ? " (no version declared)" : " (unresolvable placeholder " + rawVersion + ")"));
                    continue;
                }
                String scope = text(dep, "scope");
                Dependency d = new Dependency(g, a, version, scope == null ? "" : scope, note);
                String key = g + ":" + a;
                if (seen.containsKey(key)) {
                    Dependency prev = seen.get(key);
                    warnings.add("duplicate declaration of " + key + ": keeping " + prev.version()
                            + ", ignoring " + version);
                } else {
                    seen.put(key, d);
                    deps.add(d);
                }
            }
        }
        return new ParseResult(List.copyOf(deps), List.copyOf(warnings));
    }

    private static Document load(Path pomFile) throws PomException {
        if (!Files.isRegularFile(pomFile)) {
            throw new PomException("pom.xml not found: " + pomFile);
        }
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(false);
            // XXE hardening: poms must not carry doctypes/entities
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            DocumentBuilder b = f.newDocumentBuilder();
            try (var in = Files.newInputStream(pomFile)) {
                return b.parse(in);
            }
        } catch (Exception e) {
            throw new PomException("malformed pom.xml (" + pomFile + "): " + e.getMessage(), e);
        }
    }

    /** Resolve ${...} placeholders against properties (cycle-safe, leaves unknowns intact). */
    static String resolve(String value, Map<String, String> properties) {
        String out = value;
        for (int round = 0; round < 10; round++) {
            Matcher m = PLACEHOLDER.matcher(out);
            StringBuffer sb = new StringBuffer();
            boolean changed = false;
            while (m.find()) {
                String replacement = properties.get(m.group(1));
                if (replacement != null) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
                    changed = true;
                } else {
                    m.appendReplacement(sb, Matcher.quoteReplacement(m.group(0)));
                }
            }
            m.appendTail(sb);
            out = sb.toString();
            if (!changed) break;
        }
        return out;
    }

    private static List<Element> childElements(Element parent) {
        List<Element> out = new ArrayList<>();
        var nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i) instanceof Element e) out.add(e);
        }
        return out;
    }

    private static List<Element> directChildren(Element parent, String tag) {
        List<Element> out = new ArrayList<>();
        for (Element e : childElements(parent)) {
            if (tag.equals(e.getTagName())) out.add(e);
        }
        return out;
    }

    private static String text(Element parent, String tag) {
        for (Element e : directChildren(parent, tag)) {
            return e.getTextContent().trim();
        }
        return null;
    }

    /** Resolve the pom path from a CLI input: a pom file itself or a project directory. */
    public static Path resolvePomInput(Path input) throws PomException, IOException {
        if (Files.isDirectory(input)) {
            Path pom = input.resolve("pom.xml");
            if (!Files.isRegularFile(pom)) {
                throw new PomException("no pom.xml found in directory: " + input);
            }
            return pom;
        }
        if (!Files.isRegularFile(input)) {
            throw new PomException("input not found: " + input);
        }
        return input;
    }
}
