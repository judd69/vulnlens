package dev.vulnlens.buildtools;

import dev.vulnlens.model.Dependency;
import dev.vulnlens.model.ScanResult;
import dev.vulnlens.model.VulnRecord;
import dev.vulnlens.osv.OsvMapper;
import dev.vulnlens.parse.PomParser;
import dev.vulnlens.report.HtmlReport;
import dev.vulnlens.scan.ScanEngine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Build-time helper (NOT shipped in vulnlens.jar): regenerates
 * docs/sample-report.html from the checked-in OSV.dev fixture through
 * VulnLens's real parse → map → score → render pipeline. The only thing
 * bypassed is the HTTP transport (see tools/osv-fixture/README.md).
 *
 * Usage: FixtureMain <pom> <batch-json-fixture> <output-html>
 */
public final class FixtureMain {

    private FixtureMain() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("usage: FixtureMain <pom> <batch-json-fixture> <output-html>");
            System.exit(2);
        }
        Path pom = Path.of(args[0]);
        PomParser.ParseResult parsed = PomParser.parse(pom);
        List<Dependency> deps = parsed.dependencies();
        if (deps.isEmpty()) throw new IllegalStateException("no dependencies in " + pom);

        String batchJson = Files.readString(Path.of(args[1]), StandardCharsets.UTF_8);
        List<List<VulnRecord>> perDep = OsvMapper.parseBatch(batchJson, deps);
        if (perDep.size() != deps.size()) {
            throw new IllegalStateException("fixture has " + perDep.size()
                    + " results for " + deps.size() + " dependencies");
        }

        ScanResult result = ScanEngine.assemble("vulnerable-sample", deps, perDep, 0);
        String html = HtmlReport.render(result);
        html = injectProvenance(html);

        Path out = Path.of(args[2]);
        Files.createDirectories(out.getParent());
        Files.writeString(out, html, StandardCharsets.UTF_8);
        System.out.println("wrote " + out.toAbsolutePath()
                + " — risk " + result.riskScore() + "/100 (" + result.grade() + "), "
                + result.totalVulns() + " vulns in " + result.vulnerableDeps()
                + "/" + result.dependencies().size() + " deps");
    }

    /** Adds the clearly-labeled provenance banner the fixture approach requires. */
    private static String injectProvenance(String html) {
        String banner = """
                <div class="wrap"><p class="provenance"><strong>Sample report.</strong>
                Generated from real OSV.dev records fetched live on 2026-10-24 and verified
                against these exact versions (see <span class="mono">tools/osv-fixture/README.md</span>).
                On a normal network VulnLens queries the live OSV.dev API directly.</p></div>
                """;
        String style = "<style>.provenance{background:#131c2e;border:1px solid #2b3a5c;border-left:4px solid #7dd3fc;"
                + "border-radius:10px;padding:12px 16px;color:#aebdd6;font-size:.85rem;margin:18px auto;max-width:1080px}"
                + ".provenance .mono{font-family:ui-monospace,Menlo,Consolas,monospace}</style>\n</head>";
        html = html.replace("</head>", style);
        html = html.replace("</header>", "</header>\n" + banner);
        return html;
    }
}
