package dev.vulnlens.model;

/**
 * A single Maven dependency declared in a pom.xml, with its resolved version.
 *
 * @param groupId    Maven groupId
 * @param artifactId Maven artifactId
 * @param version    resolved version string (placeholders already expanded)
 * @param scope      Maven scope, may be empty when not declared (means compile)
 * @param note       optional provenance note, e.g. "version from dependencyManagement"
 */
public record Dependency(String groupId, String artifactId, String version, String scope, String note) {

    /** Coordinate used by OSV.dev: {@code groupId:artifactId}. */
    public String coordinate() {
        return groupId + ":" + artifactId;
    }

    public String effectiveScope() {
        return (scope == null || scope.isBlank()) ? "compile" : scope;
    }
}
