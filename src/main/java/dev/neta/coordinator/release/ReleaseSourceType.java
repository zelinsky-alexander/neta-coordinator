package dev.neta.coordinator.release;

public enum ReleaseSourceType {
    RELEASE,
    GIT_REF;

    public static ReleaseSourceType parse(String value) {
        if (value == null) return RELEASE;
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "release" -> RELEASE;
            case "git-ref", "git_ref", "ref" -> GIT_REF;
            default -> throw new IllegalArgumentException("source must be release or git-ref");
        };
    }
}
