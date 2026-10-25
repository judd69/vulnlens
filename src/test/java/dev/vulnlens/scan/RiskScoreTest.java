package dev.vulnlens.scan;

import dev.vulnlens.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.EnumMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RiskScoreTest {

    private static Map<Severity, Long> counts(long c, long h, long m, long l) {
        Map<Severity, Long> map = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) map.put(s, 0L);
        map.put(Severity.CRITICAL, c);
        map.put(Severity.HIGH, h);
        map.put(Severity.MEDIUM, m);
        map.put(Severity.LOW, l);
        return map;
    }

    @Test
    void formulaAndCap() {
        // the vulnerable-sample shape: 8 critical, 1 high, 1 medium
        RiskScore.Breakdown b = RiskScore.compute(counts(8, 1, 1, 0));
        assertEquals(214, b.raw());
        assertEquals(100, b.score());
        assertEquals("Critical", b.grade());
    }

    @Test
    void uncappedScore() {
        RiskScore.Breakdown b = RiskScore.compute(counts(1, 1, 1, 1));
        assertEquals(40, b.raw());
        assertEquals(40, b.score());
        assertEquals("High", b.grade());
    }

    @Test
    void emptyIsZeroLow() {
        RiskScore.Breakdown b = RiskScore.compute(counts(0, 0, 0, 0));
        assertEquals(0, b.score());
        assertEquals("Low", b.grade());
    }

    @ParameterizedTest
    @CsvSource({"0,Low", "19,Low", "20,Moderate", "39,Moderate", "40,High", "69,High", "70,Critical", "100,Critical"})
    void gradeBoundaries(int score, String grade) {
        assertEquals(grade, RiskScore.grade(score));
    }

    @Test
    void unknownSeverityIsUnscored() {
        Map<Severity, Long> map = counts(0, 0, 0, 0);
        map.put(Severity.UNKNOWN, 5L);
        RiskScore.Breakdown b = RiskScore.compute(map);
        assertEquals(0, b.score());
        assertEquals(5, b.unknown());
        assertTrue(RiskScore.explain(b).contains("unscored"));
    }

    @ParameterizedTest
    @CsvSource({
        "10.0, CRITICAL", "9.0, CRITICAL", "9.8, CRITICAL",
        "8.9, HIGH", "7.0, HIGH",
        "6.9, MEDIUM", "4.0, MEDIUM",
        "3.9, LOW", "0.1, LOW",
    })
    void severityBucketing(double score, Severity expected) {
        assertEquals(expected, Severity.of(score));
    }

    @Test
    void nullScoreIsUnknown() {
        assertEquals(Severity.UNKNOWN, Severity.of(null));
        assertEquals(Severity.UNKNOWN, Severity.of(0.0));
    }

    @Test
    void atLeastSemantics() {
        assertTrue(Severity.CRITICAL.atLeast(Severity.HIGH));
        assertTrue(Severity.HIGH.atLeast(Severity.HIGH));
        assertFalse(Severity.MEDIUM.atLeast(Severity.HIGH));
        assertFalse(Severity.UNKNOWN.atLeast(Severity.LOW));
    }
}
