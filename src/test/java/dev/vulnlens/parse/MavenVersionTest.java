package dev.vulnlens.parse;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MavenVersionTest {

    private static int cmp(String a, String b) {
        return MavenVersion.of(a).compareTo(MavenVersion.of(b));
    }

    @Test
    void trailingZerosAreEqual() {
        assertEquals(0, cmp("1.0", "1.0.0"));
        assertEquals(0, cmp("2.14.1", "2.14.1.0"));
    }

    @Test
    void numericOrdering() {
        assertTrue(cmp("2.14.1", "2.15.0") < 0);
        assertTrue(cmp("2.15.0", "2.16.0") < 0);
        assertTrue(cmp("2.16.0", "2.17.0") < 0);
        assertTrue(cmp("2.17.0", "2.17.1") < 0);
        assertTrue(cmp("1.9", "1.10.0") < 0);
        assertTrue(cmp("2.9.9.2", "2.9.10.3") < 0);
    }

    @Test
    void snapshotIsBeforeRelease() {
        assertTrue(cmp("1.0-SNAPSHOT", "1.0") < 0);
        assertTrue(cmp("2.0-SNAPSHOT", "2.0") < 0);
    }

    @Test
    void qualifierOrdering() {
        assertTrue(cmp("1.0-alpha", "1.0-beta") < 0);
        assertTrue(cmp("1.0-beta", "1.0-rc1") < 0);
        assertTrue(cmp("1.0-rc1", "1.0") < 0);
        assertTrue(cmp("1.0", "1.0-sp1") < 0);
    }

    @Test
    void releaseQualifierEqualsBare() {
        assertEquals(0, cmp("5.2.0.RELEASE", "5.2.0"));
        assertTrue(cmp("5.2.0.RELEASE", "5.2.20.RELEASE") < 0);
    }

    @Test
    void maxOfPicksHighest() {
        assertEquals("2.17.1", MavenVersion.maxOf(List.of("2.15.0", "2.17.1", "2.16.0")));
        assertEquals("1.10.0", MavenVersion.maxOf(List.of("1.9", "1.10.0")));
        assertNull(MavenVersion.maxOf(List.of()));
    }

    @Test
    void differentSegmentCounts() {
        assertTrue(cmp("2.3.24", "2.3.32") < 0);
        assertTrue(cmp("3.2.1", "3.2.2") < 0);
    }

    @Test
    void equalsContract() {
        assertEquals(MavenVersion.of("1.0"), MavenVersion.of("1.0.0"));
        assertNotEquals(MavenVersion.of("1.0"), MavenVersion.of("1.0.1"));
    }
}
