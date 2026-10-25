package dev.vulnlens;

import dev.vulnlens.cli.Args;
import dev.vulnlens.model.Dependency;
import dev.vulnlens.model.ScanResult;
import dev.vulnlens.osv.OsvClient;
import dev.vulnlens.osv.VulnerabilitySource;
import dev.vulnlens.parse.PomParser;
import dev.vulnlens.report.HtmlReport;
import dev.vulnlens.report.JsonReport;
import dev.vulnlens.report.TextReport;
import dev.vulnlens.scan.ScanEngine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * VulnLens — zero-dependency Java CLI that X-rays a Maven project's supply
 * chain against the live OSV.dev vulnerability database.
 *
 * <p>Exit codes: 0 ok · 1 --fail-on threshold hit · 2 bad input · 3 OSV.dev unreachable.
 */
public final class VulnLens {

    /** Injectable source for tests/build tooling; null means the live OSV.dev API. */
    static VulnerabilitySource sourceOverride;

    private VulnLens() {}

    public static void main(String[] args) {
        System.exit(run(args));
    }

    /** Runs the CLI, returning the process exit code (testable without System.exit). */
    public static int run(String[] args) {
        Args.Config cfg;
        try {
            cfg = Args.parse(args);
        } catch (Args.UsageException e) {
            String msg = e.getMessage();
            boolean help = msg.startsWith("Usage:") || msg.startsWith("vulnlens ");
            (help ? System.out : System.err).println(msg);
            return help ? 0 : 2;
        }

        Path pom;
        try {
            pom = PomParser.resolvePomInput(Path.of(cfg.input()));
        } catch (Exception e) {
            err("error: " + e.getMessage());
            return 2;
        }

        PomParser.ParseResult parsed;
        try {
            parsed = PomParser.parse(pom);
        } catch (PomParser.PomException e) {
            err("error: " + e.getMessage());
            return 2;
        }
        List<Dependency> deps = parsed.dependencies();
        for (String w : parsed.warnings()) {
            if (!cfg.quiet()) err("warning: " + w);
        }
        if (deps.isEmpty()) {
            err("error: no scannable dependencies found in " + pom);
            return 2;
        }
        if (!cfg.quiet()) {
            err("vulnlens: scanning " + deps.size() + " dependencies from " + pom.getFileName()
                    + " against OSV.dev …");
        }

        VulnerabilitySource source = sourceOverride != null ? sourceOverride : new OsvClient(cfg.timeout());
        ScanResult result;
        try {
            String projectName = projectName(pom);
            result = ScanEngine.scan(projectName, deps, source);
        } catch (VulnerabilitySource.OsvException e) {
            err("error: " + e.getMessage());
            return 3;
        }

        String report = switch (cfg.format()) {
            case HTML -> HtmlReport.render(result);
            case JSON -> JsonReport.render(result);
            case TEXT -> TextReport.render(result, !cfg.noColor());
        };

        String output = cfg.output() != null ? cfg.output() : Args.defaultOutput(cfg.format());
        try {
            if (output.equals("-")) {
                if (cfg.format() == Args.Format.HTML) {
                    err("error: --format html needs a file; use --output <path> (stdout makes no sense for HTML)");
                    return 2;
                }
                System.out.print(report);
            } else {
                Path out = Path.of(output);
                Files.writeString(out, report, StandardCharsets.UTF_8);
                if (!cfg.quiet()) {
                    String summary = "risk " + result.riskScore() + "/100 (" + result.grade() + "), "
                            + result.totalVulns() + " vulns in " + result.vulnerableDeps()
                            + "/" + result.dependencies().size() + " deps";
                    System.out.println("vulnlens: wrote " + out.toAbsolutePath() + " — " + summary);
                } else if (cfg.format() != Args.Format.TEXT || !output.equals("-")) {
                    System.out.println(out.toAbsolutePath());
                }
            }
        } catch (Exception e) {
            err("error: cannot write output: " + e.getMessage());
            return 2;
        }

        if (cfg.failOn() != null && ScanEngine.meetsFailOn(result, cfg.failOn())) {
            if (!cfg.quiet()) err("vulnlens: --fail-on " + cfg.failOn().label() + " threshold hit");
            return 1;
        }
        return 0;
    }

    private static String projectName(Path pom) {
        Path dir = pom.toAbsolutePath().getParent();
        String name = dir != null ? dir.getFileName().toString() : "project";
        return name.isBlank() ? "project" : name;
    }

    private static void err(String msg) {
        System.err.println(msg);
    }
}
