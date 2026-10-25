package dev.vulnlens.osv;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * CVSS base-score computation from the score strings found in OSV.dev
 * {@code severity[]} entries. Handles three shapes:
 * <ul>
 *   <li>plain numeric strings such as {@code "9.8"} — parsed directly;</li>
 *   <li>CVSS v3.x vectors ({@code CVSS:3.1/...}) — exact base-score algorithm
 *       per the FIRST CVSS v3.1 specification (temporal/environmental metrics ignored);</li>
 *   <li>CVSS v4.0 vectors ({@code CVSS:4.0/...}) — port of the official FIRST
 *       cvss-v4-calculator (BSD-2-Clause, (c) FIRST, Red Hat and contributors).</li>
 * </ul>
 * Returns {@code null} when no score can be derived.
 */
public final class Cvss {

    private Cvss() {}

    /** Derive a base score from a type/score pair as found in OSV severity entries. */
    public static Double score(String type, String score) {
        if (score == null || score.isBlank()) return null;
        String s = score.trim();
        try {
            double d = Double.parseDouble(s);
            if (d >= 0.0 && d <= 10.0) return d;
            return null;
        } catch (NumberFormatException ignored) {
            // not numeric: try vector forms
        }
        if (s.startsWith("CVSS:3.0/") || s.startsWith("CVSS:3.1/")) {
            return v3BaseScore(s);
        }
        if (s.startsWith("CVSS:4.0/")) {
            return v4BaseScore(s);
        }
        return null;
    }

    // ------------------------------------------------------------------
    // CVSS v3.x — exact base score per FIRST CVSS v3.1 spec
    // ------------------------------------------------------------------

    private static String v3Val(String vector, String metric) {
        for (String part : vector.split("/")) {
            int c = part.indexOf(':');
            if (c > 0 && part.substring(0, c).equals(metric)) return part.substring(c + 1);
        }
        return null;
    }

    private static double v3BaseScore(String vector) {
        // Required base metrics; absent metric -> cannot score
        String av = v3Val(vector, "AV"), ac = v3Val(vector, "AC"), pr = v3Val(vector, "PR"),
               ui = v3Val(vector, "UI"), s = v3Val(vector, "S"),
               c = v3Val(vector, "C"), i = v3Val(vector, "I"), a = v3Val(vector, "A");
        if (av == null || ac == null || pr == null || ui == null || s == null
                || c == null || i == null || a == null) return Double.NaN;

        double avW = w(Map.of("N", 0.85, "A", 0.62, "L", 0.55, "P", 0.2), av);
        double acW = w(Map.of("L", 0.77, "H", 0.44), ac);
        double prW = w(Map.of("N", 0.85, "L", s.equals("U") ? 0.62 : 0.68, "H", s.equals("U") ? 0.27 : 0.5), pr);
        double uiW = w(Map.of("N", 0.85, "R", 0.62), ui);
        double cW = w(Map.of("N", 0.0, "L", 0.22, "H", 0.56), c);
        double iW = w(Map.of("N", 0.0, "L", 0.22, "H", 0.56), i);
        double aW = w(Map.of("N", 0.0, "L", 0.22, "H", 0.56), a);
        if (Double.isNaN(avW + acW + prW + uiW + cW + iW + aW)) return Double.NaN;

        double iss = 1.0 - (1 - cW) * (1 - iW) * (1 - aW);
        double impact, exploitability = 8.22 * avW * acW * prW * uiW;
        double base;
        if (s.equals("U")) {
            impact = 6.42 * iss;
            base = Math.min(impact + exploitability, 10.0);
        } else {
            impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
            if (impact <= 0) return 0.0;
            base = Math.min(1.08 * (impact + exploitability), 10.0);
        }
        // roundup to 1 decimal per spec
        double rounded = Math.ceil(base * 100000) / 100000;
        return Math.ceil(rounded * 10) / 10.0;
    }

    private static double w(Map<String, Double> table, String key) {
        Double d = table.get(key);
        return d == null ? Double.NaN : d;
    }

    // ------------------------------------------------------------------
    // CVSS v4.0 — port of the official FIRST cvss-v4-calculator
    // (BSD-2-Clause (c) FIRST, Red Hat and contributors)
    // ------------------------------------------------------------------

    /** macroVector -> base score lookup (270 entries from the official calculator). */
    private static final Map<String, Double> LOOKUP = buildLookup();

    private static Map<String, Double> buildLookup() {
        // "macro=score;..." compact encoding of cvssLookup_global from the official calculator
        String data = LookupData.DATA;
        Map<String, Double> map = new HashMap<>();
        for (String pair : data.split(";")) {
            int eq = pair.indexOf('=');
            if (eq > 0) map.put(pair.substring(0, eq), Double.parseDouble(pair.substring(eq + 1)));
        }
        return map;
    }

    // maxComposed tables from the official calculator
    private static final Map<Integer, String[]> EQ1_MAX = Map.of(
            0, new String[]{"AV:N/PR:N/UI:N/"},
            1, new String[]{"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"},
            2, new String[]{"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"});
    private static final Map<Integer, String[]> EQ2_MAX = Map.of(
            0, new String[]{"AC:L/AT:N/"},
            1, new String[]{"AC:H/AT:N/", "AC:L/AT:P/"});
    // eq3 -> (eq6 -> vectors)
    private static final Map<Integer, Map<Integer, String[]>> EQ3_MAX = Map.of(
            0, Map.of(0, new String[]{"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"},
                         1, new String[]{"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"}),
            1, Map.of(0, new String[]{"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"},
                         1, new String[]{"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                                          "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                                          "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"}),
            2, Map.of(1, new String[]{"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"}));
    private static final Map<Integer, String[]> EQ4_MAX = Map.of(
            0, new String[]{"SC:H/SI:S/SA:S/"},
            1, new String[]{"SC:H/SI:H/SA:H/"},
            2, new String[]{"SC:L/SI:L/SA:L/"});
    private static final Map<Integer, String[]> EQ5_MAX = Map.of(
            0, new String[]{"E:A/"}, 1, new String[]{"E:P/"}, 2, new String[]{"E:U/"});

    // maxSeverity tables from the official calculator
    private static final Map<Integer, Integer> SEV_EQ1 = Map.of(0, 1, 1, 4, 2, 5);
    private static final Map<Integer, Integer> SEV_EQ2 = Map.of(0, 1, 1, 2);
    private static final Map<Integer, Map<Integer, Integer>> SEV_EQ3EQ6 =
            Map.of(0, Map.of(0, 7, 1, 6), 1, Map.of(0, 8, 1, 8), 2, Map.of(1, 10));
    private static final Map<Integer, Integer> SEV_EQ4 = Map.of(0, 6, 1, 5, 2, 4);

    private static final Map<String, Double> AV_L = Map.of("N", 0.0, "A", 0.1, "L", 0.2, "P", 0.3);
    private static final Map<String, Double> PR_L = Map.of("N", 0.0, "L", 0.1, "H", 0.2);
    private static final Map<String, Double> UI_L = Map.of("N", 0.0, "P", 0.1, "A", 0.2);
    private static final Map<String, Double> AC_L = Map.of("L", 0.0, "H", 0.1);
    private static final Map<String, Double> AT_L = Map.of("N", 0.0, "P", 0.1);
    private static final Map<String, Double> V_L = Map.of("H", 0.0, "L", 0.1, "N", 0.2);
    private static final Map<String, Double> SC_L = Map.of("H", 0.1, "L", 0.2, "N", 0.3);
    private static final Map<String, Double> S_L = Map.of("S", 0.0, "H", 0.1, "L", 0.2, "N", 0.3);
    private static final Map<String, Double> CR_L = Map.of("H", 0.0, "M", 0.1, "L", 0.2);

    private static Double v4BaseScore(String vector) {
        Map<String, String> m = parseVector(vector);
        if (m == null) return Double.NaN;
        // no-impact shortcut
        boolean noImpact = true;
        for (String k : new String[]{"VC", "VI", "VA", "SC", "SI", "SA"}) {
            if (!"N".equals(metric(m, k))) { noImpact = false; break; }
        }
        if (noImpact) return 0.0;

        String macro = macroVector(m);
        if (macro.length() != 6) return Double.NaN;
        Double value = LOOKUP.get(macro);
        if (value == null) return Double.NaN;

        int eq1 = macro.charAt(0) - '0', eq2 = macro.charAt(1) - '0', eq3 = macro.charAt(2) - '0',
            eq4 = macro.charAt(3) - '0', eq5 = macro.charAt(4) - '0', eq6 = macro.charAt(5) - '0';

        Double sEq1Low = LOOKUP.get("" + (eq1 + 1) + eq2 + eq3 + eq4 + eq5 + eq6);
        Double sEq2Low = LOOKUP.get("" + eq1 + (eq2 + 1) + eq3 + eq4 + eq5 + eq6);
        Double sEq3eq6Low;
        if (eq3 == 0 && eq6 == 0) {
            Double left = LOOKUP.get("" + eq1 + eq2 + eq3 + eq4 + eq5 + (eq6 + 1));
            Double right = LOOKUP.get("" + eq1 + eq2 + (eq3 + 1) + eq4 + eq5 + eq6);
            sEq3eq6Low = maxOpt(left, right);
        } else if (eq3 == 1 && eq6 == 0) {
            sEq3eq6Low = LOOKUP.get("" + eq1 + eq2 + eq3 + eq4 + eq5 + (eq6 + 1));
        } else {
            sEq3eq6Low = LOOKUP.get("" + eq1 + eq2 + (eq3 + 1) + eq4 + eq5 + eq6);
        }
        Double sEq4Low = LOOKUP.get("" + eq1 + eq2 + eq3 + (eq4 + 1) + eq5 + eq6);
        Double sEq5Low = LOOKUP.get("" + eq1 + eq2 + eq3 + eq4 + (eq5 + 1) + eq6);

        // find the max vector >= our vector (severity distance)
        String[] eq1Maxes = EQ1_MAX.get(eq1), eq2Maxes = EQ2_MAX.get(eq2),
                 eq4Maxes = EQ4_MAX.get(eq4), eq5Maxes = EQ5_MAX.get(eq5);
        String[] eq3eq6Maxes = EQ3_MAX.get(eq3).get(eq6);
        String chosen = null;
        outer:
        for (String a : eq1Maxes) for (String b : eq2Maxes) for (String c : eq3eq6Maxes)
                for (String d : eq4Maxes) for (String e : eq5Maxes) {
            String maxVector = a + b + c + d + e;
            if (severityDistancesNonNegative(m, maxVector)) { chosen = maxVector; break outer; }
        }
        if (chosen == null) return Double.NaN;

        double dAV = lvl(AV_L, m, "AV") - lvl(AV_L, chosen, "AV");
        double dPR = lvl(PR_L, m, "PR") - lvl(PR_L, chosen, "PR");
        double dUI = lvl(UI_L, m, "UI") - lvl(UI_L, chosen, "UI");
        double dAC = lvl(AC_L, m, "AC") - lvl(AC_L, chosen, "AC");
        double dAT = lvl(AT_L, m, "AT") - lvl(AT_L, chosen, "AT");
        double dVC = lvl(V_L, m, "VC") - lvl(V_L, chosen, "VC");
        double dVI = lvl(V_L, m, "VI") - lvl(V_L, chosen, "VI");
        double dVA = lvl(V_L, m, "VA") - lvl(V_L, chosen, "VA");
        double dSC = lvl(SC_L, m, "SC") - lvl(SC_L, chosen, "SC");
        double dSI = lvl(S_L, m, "SI") - lvl(S_L, chosen, "SI");
        double dSA = lvl(S_L, m, "SA") - lvl(S_L, chosen, "SA");
        double dCR = lvl(CR_L, m, "CR") - lvl(CR_L, chosen, "CR");
        double dIR = lvl(CR_L, m, "IR") - lvl(CR_L, chosen, "IR");
        double dAR = lvl(CR_L, m, "AR") - lvl(CR_L, chosen, "AR");

        double distEq1 = dAV + dPR + dUI;
        double distEq2 = dAC + dAT;
        double distEq3eq6 = dVC + dVI + dVA + dCR + dIR + dAR;
        double distEq4 = dSC + dSI + dSA;

        double step = 0.1;
        double maxEq1 = SEV_EQ1.get(eq1) * step, maxEq2 = SEV_EQ2.get(eq2) * step,
               maxEq3eq6 = SEV_EQ3EQ6.get(eq3).get(eq6) * step, maxEq4 = SEV_EQ4.get(eq4) * step;

        double mean = 0; int n = 0;
        if (sEq1Low != null) { n++; mean += (value - sEq1Low) * (distEq1 / maxEq1); }
        if (sEq2Low != null) { n++; mean += (value - sEq2Low) * (distEq2 / maxEq2); }
        if (sEq3eq6Low != null) { n++; mean += (value - sEq3eq6Low) * (distEq3eq6 / maxEq3eq6); }
        if (sEq4Low != null) { n++; mean += (value - sEq4Low) * (distEq4 / maxEq4); }
        if (sEq5Low != null) { n++; /* eq5 contributes 0 */ }
        if (n > 0) mean /= n;

        double result = value - mean;
        if (result < 0) result = 0;
        if (result > 10) result = 10;
        return Math.round(result * 10) / 10.0;
    }

    private static Double maxOpt(Double a, Double b) {
        if (a == null) return b;
        if (b == null) return a;
        return Math.max(a, b);
    }

    private static Map<String, String> parseVector(String vector) {
        Map<String, String> map = new LinkedHashMap<>();
        for (String part : vector.split("/")) {
            if (part.startsWith("CVSS:")) continue;
            int c = part.indexOf(':');
            if (c <= 0) return null;
            map.put(part.substring(0, c), part.substring(c + 1));
        }
        // required base metrics
        for (String k : new String[]{"AV","PR","UI","AC","AT","VC","VI","VA","SC","SI","SA"}) {
            if (!map.containsKey(k)) return null;
        }
        return map;
    }

    /** The m() function from the official calculator: metric with env/modified overrides. */
    private static String metric(Map<String, String> m, String metric) {
        String sel = m.get(metric);
        if (sel == null) sel = "X";
        if (metric.equals("E") && sel.equals("X")) return "A";
        if ((metric.equals("CR") || metric.equals("IR") || metric.equals("AR")) && sel.equals("X")) return "H";
        String mod = m.get("M" + metric);
        if (mod != null && !mod.equals("X")) return mod;
        return sel;
    }

    private static String macroVector(Map<String, String> m) {
        String eq1, eq2, eq3 = null, eq4 = null, eq5, eq6;
        String av = metric(m, "AV"), pr = metric(m, "PR"), ui = metric(m, "UI");
        if (av.equals("N") && pr.equals("N") && ui.equals("N")) eq1 = "0";
        else if ((av.equals("N") || pr.equals("N") || ui.equals("N"))
                && !(av.equals("N") && pr.equals("N") && ui.equals("N")) && !av.equals("P")) eq1 = "1";
        else if (av.equals("P") || !(av.equals("N") || pr.equals("N") || ui.equals("N"))) eq1 = "2";
        else return "";

        String ac = metric(m, "AC"), at = metric(m, "AT");
        eq2 = (ac.equals("L") && at.equals("N")) ? "0" : "1";

        String vc = metric(m, "VC"), vi = metric(m, "VI"), va = metric(m, "VA");
        if (vc.equals("H") && vi.equals("H")) eq3 = "0";
        else if (!(vc.equals("H") && vi.equals("H")) && (vc.equals("H") || vi.equals("H") || va.equals("H"))) eq3 = "1";
        else if (!(vc.equals("H") || vi.equals("H") || va.equals("H"))) eq3 = "2";
        else return "";

        String msi = m.getOrDefault("MSI", "X"), msa = m.getOrDefault("MSA", "X");
        String sc = metric(m, "SC"), si = metric(m, "SI"), sa = metric(m, "SA");
        if (msi.equals("S") || msa.equals("S")) eq4 = "0";
        else if (!(msi.equals("S") || msa.equals("S")) && (sc.equals("H") || si.equals("H") || sa.equals("H"))) eq4 = "1";
        else if (!(msi.equals("S") || msa.equals("S")) && !(sc.equals("H") || si.equals("H") || sa.equals("H"))) eq4 = "2";
        else return "";

        String e = metric(m, "E");
        eq5 = e.equals("A") ? "0" : e.equals("P") ? "1" : e.equals("U") ? "2" : "";

        String cr = metric(m, "CR"), ir = metric(m, "IR"), ar = metric(m, "AR");
        if ((cr.equals("H") && vc.equals("H")) || (ir.equals("H") && vi.equals("H")) || (ar.equals("H") && va.equals("H"))) eq6 = "0";
        else eq6 = "1";

        if (eq5.isEmpty()) return "";
        return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
    }

    private static double lvl(Map<String, Double> table, Map<String, String> vec, String metric) {
        String v = metric(vec, metric);
        Double d = table.get(v);
        if (d == null) throw new IllegalArgumentException("bad metric value " + metric + ":" + v);
        return d;
    }

    private static double lvl(Map<String, Double> table, String maxVector, String metric) {
        String v = v3Val(maxVector, metric);
        Double d = table.get(v);
        if (d == null) throw new IllegalArgumentException("bad metric value " + metric + ":" + v);
        return d;
    }

    private static boolean severityDistancesNonNegative(Map<String, String> m, String maxVector) {
        String[][] pairs = {
            {"AV", "AV_L"}, {"PR", "PR_L"}, {"UI", "UI_L"}, {"AC", "AC_L"}, {"AT", "AT_L"},
            {"VC", "V_L"}, {"VI", "V_L"}, {"VA", "V_L"},
            {"SC", "SC_L"}, {"SI", "S_L"}, {"SA", "S_L"},
            {"CR", "CR_L"}, {"IR", "CR_L"}, {"AR", "CR_L"}};
        for (String[] p : pairs) {
            Map<String, Double> table = switch (p[1]) {
                case "AV_L" -> AV_L; case "PR_L" -> PR_L; case "UI_L" -> UI_L;
                case "AC_L" -> AC_L; case "AT_L" -> AT_L; case "V_L" -> V_L;
                case "SC_L" -> SC_L; case "S_L" -> S_L; default -> CR_L;
            };
            if (lvl(table, m, p[0]) - lvl(table, maxVector, p[0]) < 0) return false;
        }
        return true;
    }

    /** Compact encoding of the official cvssLookup_global table (270 entries). */
    private static final class LookupData {
        static final String DATA =
            "000000=10.0;000001=9.9;000010=9.8;000011=9.5;000020=9.5;000021=9.2;000100=10.0;000101=9.6;000110=9.3;000111=8.7;000120=9.1;000121=8.1;000200=9.3;000201=9.0;000210=8.9;000211=8.0;000220=8.1;000221=6.8;001000=9.8;001001=9.5;001010=9.5;001011=9.2;001020=9.0;001021=8.4;001100=9.3;001101=9.2;001110=8.9;001111=8.1;001120=8.1;001121=6.5;001200=8.8;001201=8.0;001210=7.8;001211=7.0;001220=6.9;001221=4.8;002001=9.2;002011=8.2;002021=7.2;002101=7.9;002111=6.9;002121=5.0;002201=6.9;002211=5.5;002221=2.7;010000=9.9;010001=9.7;010010=9.5;010011=9.2;010020=9.2;010021=8.5;010100=9.5;010101=9.1;010110=9.0;010111=8.3;010120=8.4;010121=7.1;010200=9.2;010201=8.1;010210=8.2;010211=7.1;010220=7.2;010221=5.3;011000=9.5;011001=9.3;011010=9.2;011011=8.5;011020=8.5;011021=7.3;011100=9.2;011101=8.2;011110=8.0;011111=7.2;011120=7.0;011121=5.9;011200=8.4;011201=7.0;011210=7.1;011211=5.2;011220=5.0;011221=3.0;012001=8.6;012011=7.5;012021=5.2;012101=7.1;012111=5.2;012121=2.9;012201=6.3;012211=2.9;012221=1.7;100000=9.8;100001=9.5;100010=9.4;100011=8.7;100020=9.1;100021=8.1;100100=9.4;100101=8.9;100110=8.6;100111=7.4;100120=7.7;100121=6.4;100200=8.7;100201=7.5;100210=7.4;100211=6.3;100220=6.3;100221=4.9;101000=9.4;101001=8.9;101010=8.8;101011=7.7;101020=7.6;101021=6.7;101100=8.6;101101=7.6;101110=7.4;101111=5.8;101120=5.9;101121=5.0;101200=7.2;101201=5.7;101210=5.7;101211=5.2;101220=5.2;101221=2.5;102001=8.3;102011=7.0;102021=5.4;102101=6.5;102111=5.8;102121=2.6;102201=5.3;102211=2.1;102221=1.3;110000=9.5;110001=9.0;110010=8.8;110011=7.6;110020=7.6;110021=7.0;110100=9.0;110101=7.7;110110=7.5;110111=6.2;110120=6.1;110121=5.3;110200=7.7;110201=6.6;110210=6.8;110211=5.9;110220=5.2;110221=3.0;111000=8.9;111001=7.8;111010=7.6;111011=6.7;111020=6.2;111021=5.8;111100=7.4;111101=5.9;111110=5.7;111111=5.7;111120=4.7;111121=2.3;111200=6.1;111201=5.2;111210=5.7;111211=2.9;111220=2.4;111221=1.6;112001=7.1;112011=5.9;112021=3.0;112101=5.8;112111=2.6;112121=1.5;112201=2.3;112211=1.3;112221=0.6;200000=9.3;200001=8.7;200010=8.6;200011=7.2;200020=7.5;200021=5.8;200100=8.6;200101=7.4;200110=7.4;200111=6.1;200120=5.6;200121=3.4;200200=7.0;200201=5.4;200210=5.2;200211=4.0;200220=4.0;200221=2.2;201000=8.5;201001=7.5;201010=7.4;201011=5.5;201020=6.2;201021=5.1;201100=7.2;201101=5.7;201110=5.5;201111=4.1;201120=4.6;201121=1.9;201200=5.3;201201=3.6;201210=3.4;201211=1.9;201220=1.9;201221=0.8;202001=6.4;202011=5.1;202021=2.0;202101=4.7;202111=2.1;202121=1.1;202201=2.4;202211=0.9;202221=0.4;210000=8.8;210001=7.5;210010=7.3;210011=5.3;210020=6.0;210021=5.0;210100=7.3;210101=5.5;210110=5.9;210111=4.0;210120=4.1;210121=2.0;210200=5.4;210201=4.3;210210=4.5;210211=2.2;210220=2.0;210221=1.1;211000=7.5;211001=5.5;211010=5.8;211011=4.5;211020=4.0;211021=2.1;211100=6.1;211101=5.1;211110=4.8;211111=1.8;211120=2.0;211121=0.9;211200=4.6;211201=1.8;211210=1.7;211211=0.7;211220=0.8;211221=0.2;212001=5.3;212011=2.4;212021=1.4;212101=2.4;212111=1.2;212121=0.5;212201=1.0;212211=0.3;212221=0.1";
    }
}
