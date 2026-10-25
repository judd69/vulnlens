package dev.vulnlens.parse;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Maven version ordering, following the rules of Maven's {@code ComparableVersion}:
 * numeric segments compare numerically; qualifier segments compare by the well-known
 * qualifier order (alpha &lt; beta &lt; milestone &lt; rc &lt; snapshot &lt; "" &lt; sp),
 * unknown qualifiers sort after "sp" lexically; trailing null segments
 * ({@code 0}, {@code ""}, {@code final}, {@code ga}, {@code release}) are trimmed so
 * that e.g. {@code 1.0 == 1.0.0 == 1.0-ga}.
 */
public final class MavenVersion implements Comparable<MavenVersion> {

    private static final List<String> QUALIFIERS = List.of(
            "alpha", "beta", "milestone", "rc", "snapshot", "", "sp");

    private static final List<String> NULL_TOKENS = List.of("0", "", "final", "ga", "release");

    private final String original;
    private final List<Object> tokens; // Integer or String

    private MavenVersion(String original, List<Object> tokens) {
        this.original = original;
        this.tokens = tokens;
    }

    public static MavenVersion of(String version) {
        String v = version == null ? "" : version.trim().toLowerCase(Locale.ROOT);
        List<Object> tokens = new ArrayList<>();
        // Split on '.' and '-', and also on digit/non-digit transitions (e.g. "rc1" -> "rc","1").
        StringBuilder cur = new StringBuilder();
        boolean curNumeric = false;
        boolean hasCur = false;
        for (int k = 0; k < v.length(); k++) {
            char c = v.charAt(k);
            if (c == '.' || c == '-') {
                if (hasCur) { tokens.add(toToken(cur.toString(), curNumeric)); cur.setLength(0); hasCur = false; }
                continue;
            }
            boolean digit = Character.isDigit(c);
            if (hasCur && digit != curNumeric) {
                tokens.add(toToken(cur.toString(), curNumeric));
                cur.setLength(0);
            }
            cur.append(c);
            curNumeric = digit;
            hasCur = true;
        }
        if (hasCur) tokens.add(toToken(cur.toString(), curNumeric));
        // trim trailing null tokens
        int end = tokens.size();
        while (end > 0 && isNullToken(tokens.get(end - 1))) end--;
        return new MavenVersion(version == null ? "" : version.trim(), tokens.subList(0, end));
    }

    private static Object toToken(String text, boolean numeric) {
        if (numeric) {
            try {
                return Integer.parseInt(text);
            } catch (NumberFormatException e) {
                return text; // absurdly long digit run: compare lexically
            }
        }
        return text;
    }

    private static boolean isNullToken(Object t) {
        return t instanceof Integer i ? i == 0 : NULL_TOKENS.contains(t);
    }

    private static String qualifierRank(String q) {
        int idx = QUALIFIERS.indexOf(q);
        if (idx >= 0) return "0" + idx;
        return "1" + q; // unknown qualifiers sort after "sp", lexically
    }

    @Override
    public int compareTo(MavenVersion other) {
        int n = Math.max(this.tokens.size(), other.tokens.size());
        for (int k = 0; k < n; k++) {
            Object a = k < this.tokens.size() ? this.tokens.get(k) : null;
            Object b = k < other.tokens.size() ? other.tokens.get(k) : null;
            int c = compareToken(a, b);
            if (c != 0) return c;
        }
        return 0;
    }

    private static int compareToken(Object a, Object b) {
        if (a == null && b == null) return 0;
        if (a == null) return -compareToken(b, null);
        if (b == null) {
            // a missing segment behaves like the null token: 0 for numbers,
            // "" (release) for qualifiers — so 1.0-SNAPSHOT < 1.0 < 1.0-sp
            if (a instanceof Integer i) return Integer.compare(i, 0);
            return qualifierRank((String) a).compareTo(qualifierRank(""));
        }
        if (a instanceof Integer ia && b instanceof Integer ib) return ia.compareTo(ib);
        if (a instanceof Integer) return -1; // numbers sort before qualifiers
        if (b instanceof Integer) return 1;
        return qualifierRank((String) a).compareTo(qualifierRank((String) b));
    }

    public boolean isLessThan(MavenVersion other) { return compareTo(other) < 0; }
    public boolean isGreaterThan(MavenVersion other) { return compareTo(other) > 0; }

    /** Returns the greatest of the given version strings (null-safe, ignores blanks). */
    public static String maxOf(Iterable<String> versions) {
        MavenVersion best = null;
        String bestRaw = null;
        for (String v : versions) {
            if (v == null || v.isBlank()) continue;
            MavenVersion mv = MavenVersion.of(v);
            if (best == null || mv.compareTo(best) > 0) { best = mv; bestRaw = v.trim(); }
        }
        return bestRaw;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof MavenVersion mv && compareTo(mv) == 0;
    }

    @Override
    public int hashCode() { return tokens.hashCode(); }

    @Override
    public String toString() { return original; }
}
