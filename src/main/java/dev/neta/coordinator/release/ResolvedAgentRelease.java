package dev.neta.coordinator.release;

import java.time.Instant;

public record ResolvedAgentRelease(
        ReleaseSourceType sourceType,
        String sourceRef,
        String sourceCommit,
        String version,
        String buildId,
        String gitCommit,
        String os,
        String arch,
        String artifactName,
        String artifactUrl,
        String artifactSha256,
        Instant publishedAt) {}
