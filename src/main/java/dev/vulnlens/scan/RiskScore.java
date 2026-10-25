package dev.vulnlens.scan;

import dev.vulnlens.model.Severity;

/**
 * Explainable 0–100 supply-chain risk score.
 *
 * <p>Formula: 25 points per critical + 10 per high + 4 per medium + 1 per low,
 * capped at 100. Unknown-severity findings contribute nothing (they are still
 * listed, just not scored). Grades: 0–19 Low, 20–39 Moderate, 40–69 High,
 * 70–100 Critical.
 */
public final class RiskScore {

    private RiskScore() {}

    public record Breakdown(long critical, long high, long medium, long low, long unknown,
                            int raw, int score, String grade) {}

    public static Breakdown compute(java.util.Map<Severity, Long> counts) {
        long c = counts.getOrDefault(Severity.CRITICAL, 0L);
        long h = counts.getOrDefault(Severity.HIGH, 0L);
        long m = counts.getOrDefault(Severity.MEDIUM, 0L);
        long l = counts.getOrDefault(Severity.LOW, 0L);
        long u = counts.getOrDefault(Severity.UNKNOWN, 0L);
        int raw = (int) (25 * c + 10 * h + 4 * m + l);
        int score = Math.min(100, raw);
        return new Breakdown(c, h, m, l, u, raw, score, grade(score));
    }

    public static String grade(int score) {
        if (score >= 70) return "Critical";
        if (score >= 40) return "High";
        if (score >= 20) return "Moderate";
        return "Low";
    }

    /** Human-readable formula with the actual numbers, e.g. "8×25 + 1×10 + 1×4 + 0×1 = 214 → capped at 100". */
    public static String explain(Breakdown b) {
        String calc = b.critical() + "×25 + " + b.high() + "×10 + " + b.medium() + "×4 + " + b.low() + "×1"
                + " = " + b.raw();
        if (b.raw() > 100) calc += " → capped at 100";
        if (b.unknown() > 0) calc += " (" + b.unknown() + " unscored: unknown severity)";
        return calc;
    }
}
