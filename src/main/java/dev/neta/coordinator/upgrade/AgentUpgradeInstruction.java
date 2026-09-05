package dev.neta.coordinator.upgrade;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;

public record AgentUpgradeInstruction(
        @JsonProperty("upgrade_id") UUID upgradeId,
        String version,
        @JsonProperty("build_id") String buildId,
        @JsonProperty("git_commit") String gitCommit,
        String os,
        String arch,
        @JsonProperty("artifact_name") String artifactName,
        @JsonProperty("download_url") String downloadUrl,
        String sha256) {}
