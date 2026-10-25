package dev.vulnlens.model;

import java.util.List;

/**
 * One vulnerability affecting a dependency, normalised from an OSV.dev record.
 *
 * @param osvId        the OSV record id (e.g. GHSA-xxxx-yyyy-zzzz)
 * @param displayId    preferred public id: a CVE alias when present, else the OSV id
 * @param summary      short human description (may be empty)
 * @param cvss         CVSS base score, or null when the record carries no usable score
 * @param severity     bucket derived from {@code cvss}
 * @param fixedVersions fixed versions seen across the record's affected ranges (may be empty)
 * @param url          link to the record on osv.dev
 */
public record VulnRecord(
        String osvId,
        String displayId,
        String summary,
        Double cvss,
        Severity severity,
        List<String> fixedVersions,
        String url) {

    public String scoreText() {
        return cvss == null ? "n/a" : String.format("%.1f", cvss);
    }
}
