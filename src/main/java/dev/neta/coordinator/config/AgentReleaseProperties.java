package dev.neta.coordinator.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("neta.releases")
public record AgentReleaseProperties(
        String owner,
        String repository,
        String apiBase,
        String releaseTagTemplate,
        String developmentTagTemplate,
        String manifestAsset,
        String githubToken) {

    public AgentReleaseProperties {
        if (owner == null || owner.isBlank()) owner = "zelinsky-alexander";
        if (repository == null || repository.isBlank()) repository = "neta-agent";
        if (apiBase == null || apiBase.isBlank()) apiBase = "https://api.github.com";
        if (releaseTagTemplate == null || releaseTagTemplate.isBlank()) releaseTagTemplate = "v%s";
        if (developmentTagTemplate == null || developmentTagTemplate.isBlank()) developmentTagTemplate = "dev-%s";
        if (manifestAsset == null || manifestAsset.isBlank()) manifestAsset = "release-manifest.json";
        if (githubToken == null) githubToken = "";
    }

    public String releaseTag(String version) {
        return releaseTagTemplate.formatted(version);
    }

    public String developmentTag(String commitSha) {
        return developmentTagTemplate.formatted(commitSha);
    }
}
