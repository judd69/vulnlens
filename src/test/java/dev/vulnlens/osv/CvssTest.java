package dev.vulnlens.osv;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

class CvssTest {

    @Test
    void parsesNumericScore() {
        assertEquals(9.8, Cvss.score("CVSS_V3", "9.8"));
        assertEquals(0.0, Cvss.score("CVSS_V3", "0"));
    }

    @Test
    void rejectsOutOfRangeNumeric() {
        assertNull(Cvss.score("CVSS_V3", "11.0"));
        assertNull(Cvss.score("CVSS_V3", "not-a-score"));
        assertNull(Cvss.score("CVSS_V3", null));
        assertNull(Cvss.score("CVSS_V3", "  "));
    }

    /** Known CVE vectors and their FIRST-spec base scores. */
    @ParameterizedTest
    @CsvSource({
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H, 10.0",   // CVE-2021-44228
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, 9.8",    // CVE-2022-42889
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H, 9.0",    // CVE-2021-45046
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H, 6.6",    // CVE-2021-44832
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H, 10.0",   // CVE-2017-5638
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, 9.8",    // CVE-2015-7501
    })
    void v3VectorsScoreCorrectly(String vector, double expected) {
        Double got = Cvss.score("CVSS_V3", vector);
        assertNotNull(got);
        assertEquals(expected, got, 0.001, "vector " + vector);
    }

    @Test
    void v3IgnoresTemporalMetrics() {
        // same base as without /E:H
        assertEquals(10.0, Cvss.score("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H"));
    }

    @Test
    void v3ReturnsNaNForIncompleteVector() {
        Double d = Cvss.score("CVSS_V3", "CVSS:3.1/AV:N/AC:L");
        assertTrue(d == null || d.isNaN());
    }

    /** v4 vectors verified against the official FIRST cvss-v4-calculator. */
    @ParameterizedTest
    @CsvSource({
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H, 9.3",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H, 6.9",
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:U/CR:L/IR:L/AR:L, 0.1",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H, 10.0",
    })
    void v4VectorsMatchOfficialCalculator(String vector, double expected) {
        Double got = Cvss.score("CVSS_V4", vector);
        assertNotNull(got);
        assertEquals(expected, got, 0.001, "vector " + vector);
    }

    @Test
    void v4NoImpactScoresZero() {
        Double d = Cvss.score("CVSS_V4",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:A");
        assertEquals(0.0, d);
    }
}
