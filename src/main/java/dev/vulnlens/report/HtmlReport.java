package dev.vulnlens.report;

import dev.vulnlens.model.DepResult;
import dev.vulnlens.model.ScanResult;
import dev.vulnlens.model.Severity;
import dev.vulnlens.model.VulnRecord;
import dev.vulnlens.scan.RiskScore;

import java.util.EnumMap;
import java.util.Map;

/**
 * Renders a self-contained, single-file HTML report: dark security-ops theme,
 * animated risk gauge, summary cards, severity heatmap, sortable CVE table,
 * per-dependency expandable details. No external assets.
 */
public final class HtmlReport {

    private HtmlReport() {}

    public static String render(ScanResult result) {
        StringBuilder h = new StringBuilder();
        h.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        h.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        h.append("<title>VulnLens report — ").append(esc(result.projectName())).append("</title>\n");
        h.append("<style>\n").append(css()).append("</style>\n</head>\n<body>\n");
        h.append("<div class=\"bg\" aria-hidden=\"true\"></div>\n");
        h.append("<header class=\"wrap head\">\n");
        h.append("  <div class=\"brand\"><svg width=\"30\" height=\"30\" viewBox=\"0 0 24 24\" fill=\"none\" aria-hidden=\"true\">"
                + "<path d=\"M12 2l8 3.5v5.2c0 5-3.4 9.3-8 10.8-4.6-1.5-8-5.8-8-10.8V5.5L12 2z\" stroke=\"#f87171\" stroke-width=\"1.8\"/>"
                + "<circle cx=\"12\" cy=\"11\" r=\"3.2\" stroke=\"#f87171\" stroke-width=\"1.8\"/>"
                + "<line x1=\"14.4\" y1=\"13.4\" x2=\"17.5\" y2=\"16.5\" stroke=\"#f87171\" stroke-width=\"1.8\" stroke-linecap=\"round\"/></svg>"
                + "<div><div class=\"brand-name\">VulnLens</div><div class=\"brand-sub\">supply-chain X-ray</div></div></div>\n");
        h.append("  <div class=\"proj\"><div class=\"proj-label\">project</div><div class=\"proj-name\">")
                .append(esc(result.projectName())).append("</div><div class=\"proj-meta\">scanned ")
                .append(esc(result.scannedAt())).append(" · data: OSV.dev · query took ")
                .append(result.queryMillis()).append(" ms</div></div>\n");
        h.append("</header>\n");

        // risk hero
        String gradeClass = "g-" + result.grade().toLowerCase();
        h.append("<section class=\"wrap hero\">\n");
        h.append("  <div class=\"gauge-wrap\">\n");
        h.append("    <svg class=\"gauge\" viewBox=\"0 0 200 200\" role=\"img\" aria-label=\"risk score ")
                .append(result.riskScore()).append(" of 100\">\n");
        h.append("      <circle cx=\"100\" cy=\"100\" r=\"84\" class=\"gauge-track\"/>\n");
        double circ = 2 * Math.PI * 84;
        double frac = result.riskScore() / 100.0;
        h.append("      <circle cx=\"100\" cy=\"100\" r=\"84\" class=\"gauge-fill ").append(gradeClass)
                .append("\" data-frac=\"").append(String.format("%.3f", frac))
                .append("\" stroke-dasharray=\"").append(String.format("%.1f", circ))
                .append("\" stroke-dashoffset=\"").append(String.format("%.1f", circ)).append("\"/>\n");
        h.append("    </svg>\n");
        h.append("    <div class=\"gauge-num\"><span id=\"scoreNum\">0</span><small>/100</small></div>\n");
        h.append("  </div>\n");
        h.append("  <div class=\"hero-text\">\n");
        h.append("    <div class=\"grade ").append(gradeClass).append("\">").append(esc(result.grade())).append(" risk</div>\n");
        h.append("    <p class=\"formula\">").append(esc(scoreExplanation(result))).append("</p>\n");
        h.append("    <div class=\"cards\">\n");
        card(h, String.valueOf(result.dependencies().size()), "dependencies scanned");
        card(h, String.valueOf(result.totalVulns()), "vulnerabilities");
        card(h, String.valueOf(result.vulnerableDeps()), "vulnerable deps");
        long fixes = result.dependencies().stream().filter(d -> d.suggestedFix() != null).count();
        card(h, String.valueOf(fixes), "have a fix available");
        h.append("    </div>\n");
        h.append("  </div>\n");
        h.append("</section>\n");

        // severity counts
        h.append("<section class=\"wrap\"><h2>Findings by severity</h2><div class=\"sev-row\">\n");
        for (Severity s : new Severity[]{Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN}) {
            long n = result.severityCounts().getOrDefault(s, 0L);
            h.append("<div class=\"sev sev-").append(s.label()).append("\"><span class=\"sev-n\">").append(n)
                    .append("</span><span class=\"sev-l\">").append(s.label()).append("</span></div>\n");
        }
        h.append("</div></section>\n");

        // heatmap
        h.append("<section class=\"wrap\"><h2>Severity heatmap</h2>\n");
        h.append("<p class=\"hint\">Each cell counts findings for a dependency at a severity. Hover for CVE ids.</p>\n");
        h.append("<div class=\"table-scroll\"><table class=\"heat\">\n<thead><tr><th>dependency</th><th>critical</th><th>high</th><th>medium</th><th>low</th><th>unknown</th></tr></thead>\n<tbody>\n");
        for (DepResult d : result.dependencies()) {
            h.append("<tr><td class=\"mono\">").append(esc(d.dependency().coordinate()))
                    .append("<span class=\"ver\">").append(esc(d.dependency().version())).append("</span></td>");
            for (Severity s : new Severity[]{Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN}) {
                long n = d.vulns().stream().filter(v -> v.severity() == s).count();
                String ids = d.vulns().stream().filter(v -> v.severity() == s)
                        .map(VulnRecord::displayId).reduce((x, y) -> x + ", " + y).orElse("none");
                String cls = n == 0 ? "c0" : "c" + Math.min(4, (int) n) + " " + s.label();
                h.append("<td class=\"cell ").append(cls).append("\" title=\"").append(esc(ids)).append("\">")
                        .append(n == 0 ? "–" : n).append("</td>");
            }
            h.append("</tr>\n");
        }
        h.append("</tbody></table></div></section>\n");

        // CVE table
        h.append("<section class=\"wrap\"><h2>Vulnerabilities</h2>\n");
        h.append("<p class=\"hint\">Click a column header to sort. Filter: ");
        h.append("<button class=\"chip on\" data-f=\"all\">all</button>");
        for (Severity s : new Severity[]{Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN}) {
            h.append("<button class=\"chip\" data-f=\"").append(s.label()).append("\">").append(s.label()).append("</button>");
        }
        h.append("</p>\n<div class=\"table-scroll\"><table class=\"cve\" id=\"cveTable\">\n<thead><tr>");
        h.append("<th data-k=\"0\">dependency</th><th data-k=\"1\">version</th><th data-k=\"2\">severity</th>"
                + "<th data-k=\"3\">id</th><th data-k=\"4\">summary</th><th data-k=\"5\">fix</th>");
        h.append("</tr></thead>\n<tbody>\n");
        for (DepResult d : result.dependencies()) {
            for (VulnRecord v : d.vulns()) {
                double sortScore = v.cvss() == null ? -1 : v.cvss();
                h.append("<tr data-sev=\"").append(v.severity().label()).append("\">");
                h.append("<td class=\"mono\">").append(esc(d.dependency().coordinate())).append("</td>");
                h.append("<td class=\"mono\">").append(esc(d.dependency().version())).append("</td>");
                h.append("<td><span class=\"badge b-").append(v.severity().label()).append("\" data-s=\"")
                        .append(String.format("%.2f", sortScore)).append("\">").append(v.severity().label())
                        .append(" ").append(esc(v.scoreText())).append("</span></td>");
                h.append("<td class=\"mono\"><a href=\"").append(esc(v.url()))
                        .append("\" target=\"_blank\" rel=\"noopener\">").append(esc(v.displayId())).append("</a></td>");
                h.append("<td>").append(esc(v.summary())).append("</td>");
                String fix = d.suggestedFix();
                h.append("<td class=\"mono fix\">").append(fix == null ? "<span class=\"dim\">—</span>" : "→ " + esc(fix)).append("</td>");
                h.append("</tr>\n");
            }
        }
        h.append("</tbody></table></div></section>\n");

        // per-dependency details
        h.append("<section class=\"wrap\"><h2>Per-dependency details</h2>\n");
        for (DepResult d : result.dependencies()) {
            String open = d.vulnerable() ? " open" : "";
            h.append("<details class=\"dep\"").append(open).append("><summary>");
            h.append("<span class=\"mono\">").append(esc(d.dependency().coordinate())).append("</span>");
            h.append("<span class=\"ver\">").append(esc(d.dependency().version())).append("</span>");
            if (!d.dependency().effectiveScope().equals("compile")) {
                h.append("<span class=\"scope\">").append(esc(d.dependency().effectiveScope())).append("</span>");
            }
            if (d.vulnerable()) {
                h.append("<span class=\"dep-n bad\">").append(d.vulns().size()).append(" vuln")
                        .append(d.vulns().size() == 1 ? "" : "s").append("</span>");
                if (d.suggestedFix() != null) {
                    h.append("<span class=\"dep-fix\">upgrade → ").append(esc(d.suggestedFix())).append("</span>");
                }
            } else {
                h.append("<span class=\"dep-n ok\">clean</span>");
            }
            h.append("</summary>\n<div class=\"dep-body\">\n");
            if (!d.dependency().note().isBlank()) {
                h.append("<p class=\"note\">").append(esc(d.dependency().note())).append("</p>\n");
            }
            if (d.vulnerable()) {
                h.append("<ul>\n");
                for (VulnRecord v : d.vulns()) {
                    h.append("<li><span class=\"badge b-").append(v.severity().label()).append("\">")
                            .append(v.severity().label()).append(" ").append(esc(v.scoreText())).append("</span> ");
                    h.append("<a class=\"mono\" href=\"").append(esc(v.url()))
                            .append("\" target=\"_blank\" rel=\"noopener\">").append(esc(v.displayId())).append("</a>");
                    if (!v.summary().isBlank()) h.append(" — ").append(esc(v.summary()));
                    if (!v.fixedVersions().isEmpty()) {
                        h.append("<div class=\"fixedin\">fixed in: <span class=\"mono\">")
                                .append(esc(String.join(", ", v.fixedVersions()))).append("</span></div>");
                    }
                    h.append("</li>\n");
                }
                h.append("</ul>\n");
            } else {
                h.append("<p class=\"note\">No known vulnerabilities in OSV.dev for this version.</p>\n");
            }
            h.append("</div></details>\n");
        }
        h.append("</section>\n");

        h.append("<footer class=\"wrap foot\">\n");
        h.append("<p>Generated by <strong>VulnLens</strong> — zero-dependency Java supply-chain scanner. ")
                .append("Vulnerability data: <a href=\"https://osv.dev\" target=\"_blank\" rel=\"noopener\">OSV.dev</a>, queried live at ")
                .append(esc(result.scannedAt())).append(".</p>\n");
        h.append("<p class=\"dim\">Scores: CVSS base scores from OSV records (v3.x computed per FIRST spec, v4.0 per the official FIRST calculator). ")
                .append("Risk score = 25×critical + 10×high + 4×medium + 1×low, capped at 100.</p>\n");
        h.append("</footer>\n");
        h.append("<script>\n").append(js(result.riskScore())).append("</script>\n");
        h.append("</body>\n</html>\n");
        return h.toString();
    }

    private static void card(StringBuilder h, String num, String label) {
        h.append("<div class=\"card\"><span class=\"card-n\">").append(esc(num))
                .append("</span><span class=\"card-l\">").append(esc(label)).append("</span></div>\n");
    }

    private static String scoreExplanation(ScanResult r) {
        Map<Severity, Long> c = r.severityCounts();
        RiskScore.Breakdown b = RiskScore.compute(c);
        return "Risk score " + b.score() + "/100 — " + RiskScore.explain(b) + ".";
    }

    public static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    // ------------------------------------------------------------------
    // CSS + JS (inline, no external assets)
    // ------------------------------------------------------------------

    private static String css() {
        return """
:root{
  --bg:#070b12; --panel:#0d1420; --panel2:#111a2b; --line:#1e2a42;
  --txt:#e8eef7; --dim:#8b98b0; --faint:#5b6a86;
  --crit:#f87171; --high:#fb923c; --med:#facc15; --low:#4ade80; --unk:#94a3b8;
  --accent:#f87171; --ok:#34d399;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.55;min-height:100vh}
.bg{position:fixed;inset:0;z-index:-1;background:
  radial-gradient(900px 480px at 12% -8%, rgba(248,113,113,.10), transparent 60%),
  radial-gradient(800px 420px at 88% 4%, rgba(251,146,60,.07), transparent 60%),
  radial-gradient(1000px 700px at 50% 110%, rgba(56,189,248,.06), transparent 60%)}
.wrap{max-width:1080px;margin:0 auto;padding:0 22px}
a{color:#7dd3fc}
.head{display:flex;justify-content:space-between;align-items:center;gap:18px;padding:26px 22px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px}
.brand-name{font-weight:800;font-size:1.35rem;letter-spacing:.5px}
.brand-sub{color:var(--dim);font-size:.78rem;letter-spacing:2px;text-transform:uppercase}
.proj{text-align:right}
.proj-label{font-size:.68rem;letter-spacing:2px;text-transform:uppercase;color:var(--faint)}
.proj-name{font-family:var(--mono);font-size:1.02rem;font-weight:700}
.proj-meta{color:var(--dim);font-size:.78rem}
.hero{display:flex;gap:34px;align-items:center;padding:38px 22px 30px;flex-wrap:wrap}
.gauge-wrap{position:relative;width:210px;height:210px;flex:none}
.gauge{width:210px;height:210px;transform:rotate(-90deg)}
.gauge-track{fill:none;stroke:var(--line);stroke-width:16}
.gauge-fill{fill:none;stroke-width:16;stroke-linecap:round;transition:stroke-dashoffset 1.4s cubic-bezier(.2,.8,.2,1)}
.gauge-fill.g-low{stroke:var(--ok)} .gauge-fill.g-moderate{stroke:var(--med)}
.gauge-fill.g-high{stroke:var(--high)} .gauge-fill.g-critical{stroke:var(--crit)}
.gauge-num{position:absolute;inset:0;display:flex;align-items:baseline;justify-content:center;flex-direction:row;gap:4px;padding-top:78px;font-size:3rem;font-weight:800}
.gauge-num small{font-size:1rem;color:var(--dim);font-weight:400}
.hero-text{flex:1;min-width:280px}
.grade{font-size:1.7rem;font-weight:800;letter-spacing:.5px;margin-bottom:6px}
.grade.g-low{color:var(--ok)} .grade.g-moderate{color:var(--med)}
.grade.g-high{color:var(--high)} .grade.g-critical{color:var(--crit)}
.formula{color:var(--dim);font-size:.92rem;font-family:var(--mono);margin-bottom:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;display:flex;flex-direction:column}
.card-n{font-size:1.7rem;font-weight:800}
.card-l{color:var(--dim);font-size:.8rem}
section.wrap{padding:26px 22px}
h2{font-size:1.15rem;letter-spacing:.4px;margin-bottom:4px}
.hint{color:var(--dim);font-size:.85rem;margin-bottom:14px}
.sev-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px}
.sev{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--unk);border-radius:10px;padding:12px 14px;display:flex;flex-direction:column}
.sev-n{font-size:1.6rem;font-weight:800}
.sev-l{color:var(--dim);font-size:.8rem;text-transform:capitalize}
.sev-critical{border-left-color:var(--crit)} .sev-high{border-left-color:var(--high)}
.sev-medium{border-left-color:var(--med)} .sev-low{border-left-color:var(--low)}
.table-scroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{padding:10px 14px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
thead th{background:var(--panel2);font-size:.72rem;letter-spacing:1.4px;text-transform:uppercase;color:var(--dim);cursor:default}
table.cve thead th{cursor:pointer;user-select:none}
table.cve thead th:hover{color:var(--txt)}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(125,211,252,.04)}
.mono{font-family:var(--mono);font-size:.84rem}
.ver{color:var(--dim);font-family:var(--mono);font-size:.8rem;margin-left:8px}
.scope{font-size:.68rem;border:1px solid var(--line);border-radius:20px;padding:1px 9px;margin-left:10px;color:var(--dim)}
.heat td.cell{text-align:center;font-weight:700;font-family:var(--mono);cursor:default}
.heat td.c0{color:var(--faint);font-weight:400}
.heat td.critical{background:rgba(248,113,113,.16);color:var(--crit)}
.heat td.high{background:rgba(251,146,60,.14);color:var(--high)}
.heat td.medium{background:rgba(250,204,21,.12);color:var(--med)}
.heat td.low{background:rgba(74,222,128,.10);color:var(--low)}
.heat td.unknown{background:rgba(148,163,184,.10);color:var(--unk)}
.heat td.c2,.heat td.c3,.heat td.c4{filter:saturate(1.6) brightness(1.15)}
.badge{display:inline-block;font-size:.72rem;font-weight:700;letter-spacing:.6px;text-transform:uppercase;
  border-radius:20px;padding:2px 11px;border:1px solid}
.b-critical{color:var(--crit);border-color:rgba(248,113,113,.5);background:rgba(248,113,113,.10)}
.b-high{color:var(--high);border-color:rgba(251,146,60,.5);background:rgba(251,146,60,.10)}
.b-medium{color:var(--med);border-color:rgba(250,204,21,.5);background:rgba(250,204,21,.10)}
.b-low{color:var(--low);border-color:rgba(74,222,128,.5);background:rgba(74,222,128,.10)}
.b-unknown{color:var(--unk);border-color:rgba(148,163,184,.5);background:rgba(148,163,184,.10)}
td.fix{color:var(--ok);font-weight:600}
.dim{color:var(--faint)}
.chip{background:var(--panel2);border:1px solid var(--line);color:var(--dim);border-radius:20px;
  padding:3px 13px;font-size:.76rem;cursor:pointer;margin:0 4px 4px 0}
.chip.on{background:rgba(248,113,113,.16);border-color:var(--accent);color:var(--txt)}
details.dep{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:10px;overflow:hidden}
details.dep summary{padding:13px 18px;cursor:pointer;list-style:none;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
details.dep summary::-webkit-details-marker{display:none}
details.dep summary:hover{background:rgba(125,211,252,.04)}
.dep-body{padding:4px 18px 16px;border-top:1px solid var(--line);font-size:.9rem}
.dep-body ul{list-style:none}
.dep-body li{padding:9px 0;border-bottom:1px dashed var(--line)}
.dep-body li:last-child{border-bottom:none}
.fixedin{color:var(--dim);font-size:.8rem;margin-top:3px}
.dep-n{font-size:.75rem;font-weight:700;border-radius:20px;padding:2px 11px;margin-left:auto}
.dep-n.bad{background:rgba(248,113,113,.14);color:var(--crit)}
.dep-n.ok{background:rgba(52,211,153,.12);color:var(--ok)}
.dep-fix{font-size:.78rem;color:var(--ok);font-family:var(--mono)}
.note{color:var(--dim);font-size:.85rem;padding:8px 0}
.foot{border-top:1px solid var(--line);margin-top:26px;padding:22px;color:var(--dim);font-size:.82rem}
.foot p{margin-bottom:6px}
@media (max-width:640px){.hero{flex-direction:column}.proj{text-align:left}.head{flex-direction:column;align-items:flex-start}}
""";
    }

    private static String js(int score) {
        String tpl = """
(function(){
  // animate the risk gauge + counter
  var fill=document.querySelector('.gauge-fill');
  if(fill){
    var c=2*Math.PI*84, frac=parseFloat(fill.getAttribute('data-frac')||'0');
    requestAnimationFrame(function(){requestAnimationFrame(function(){
      fill.style.strokeDashoffset=(c*(1-frac)).toFixed(1);
    });});
    var target=__SCORE__, el=document.getElementById('scoreNum'), t0=null;
    function tick(t){ if(!t0)t0=t; var p=Math.min(1,(t-t0)/1400);
      el.textContent=Math.round(target*(1-Math.pow(1-p,3))); if(p<1)requestAnimationFrame(tick); }
    requestAnimationFrame(tick);
  }
  // severity filter chips
  var chips=document.querySelectorAll('.chip');
  chips.forEach(function(ch){ ch.addEventListener('click',function(){
    chips.forEach(function(x){x.classList.remove('on')}); ch.classList.add('on');
    var f=ch.getAttribute('data-f');
    document.querySelectorAll('#cveTable tbody tr').forEach(function(tr){
      tr.style.display=(f==='all'||tr.getAttribute('data-sev')===f)?'':'none';
    });
  });});
  // sortable CVE table
  var ths=document.querySelectorAll('#cveTable thead th'), dir=1, lastK=-1;
  ths.forEach(function(th){ th.addEventListener('click',function(){
    var k=parseInt(th.getAttribute('data-k'),10);
    dir=(k===lastK)?-dir:1; lastK=k;
    var rows=Array.prototype.slice.call(document.querySelectorAll('#cveTable tbody tr'));
    rows.sort(function(a,b){
      var va,vb;
      if(k===2){ va=parseFloat(a.querySelector('.badge').getAttribute('data-s')); vb=parseFloat(b.querySelector('.badge').getAttribute('data-s')); }
      else { va=a.cells[k].textContent.trim().toLowerCase(); vb=b.cells[k].textContent.trim().toLowerCase(); }
      return (va<vb?-1:va>vb?1:0)*dir;
    });
    var tb=document.querySelector('#cveTable tbody');
    rows.forEach(function(r){tb.appendChild(r)});
  });});
})();
""";
        return tpl.replace("__SCORE__", String.valueOf(score));
    }

    /** For tests: severity counts actually rendered. */
    static Map<Severity, Long> renderedCounts(ScanResult r) {
        Map<Severity, Long> m = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) m.put(s, r.severityCounts().getOrDefault(s, 0L));
        return m;
    }
}
