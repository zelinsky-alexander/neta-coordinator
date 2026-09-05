package dev.neta.coordinator.upgrade;

import dev.neta.coordinator.release.ReleaseSourceType;
import java.time.Instant;
import java.util.UUID;

public record AgentUpgrade(
        UUID upgradeId,
        String agentId,
        String fromVersion,
        String fromBuildId,
        String fromGitCommit,
        String fromArtifactSha256,
        ReleaseSourceType sourceType,
        String sourceRef,
        String sourceCommit,
        String targetVersion,
        String targetBuildId,
        String targetGitCommit,
        String targetOs,
        String targetArch,
        String artifactName,
        String artifactUrl,
        String artifactSha256,
        AgentUpgradeStatus status,
        Instant requestedAt,
        Instant deliveredAt,
        Instant downloadStartedAt,
        Instant installStartedAt,
        Instant localHealthyAt,
        Instant confirmedAt,
        Instant failedAt,
        Instant rolledBackAt,
        String failureCode,
        String failureMessage) {}
