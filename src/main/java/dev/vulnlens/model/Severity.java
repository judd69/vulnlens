package dev.vulnlens.model;

/**
 * Severity buckets derived from a CVSS base score.
 * Thresholds follow the CVSS v3.1 qualitative severity rating scale.
 */
public enum Severity {
    CRITICAL(9.0, "critical"),
    HIGH(7.0, "high"),
    MEDIUM(4.0, "medium"),
    LOW(0.0, "low"),
    UNKNOWN(-1.0, "unknown");

    private final double threshold;
    private final String label;

    Severity(double threshold, String label) {
        this.threshold = threshold;
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** Bucket a CVSS score (null means no score was available). */
    public static Severity of(Double score) {
        if (score == null || score.isNaN()) return UNKNOWN;
        if (score >= 9.0) return CRITICAL;
        if (score >= 7.0) return HIGH;
        if (score >= 4.0) return MEDIUM;
        if (score > 0.0) return LOW;
        return UNKNOWN; // a literal 0.0 score carries no signal
    }

    public static Severity ofLevel(String level) {
        for (Severity s : values()) {
            if (s.label.equalsIgnoreCase(level)) return s;
        }
        throw new IllegalArgumentException("Unknown severity level: " + level);
    }

    /** True when this severity is at or above the given floor (UNKNOWN never qualifies). */
    public boolean atLeast(Severity floor) {
        if (this == UNKNOWN) return false;
        return this.ordinal() <= floor.ordinal();
    }
}
