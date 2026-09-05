package dev.neta.coordinator.release;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.config.AgentReleaseProperties;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class GitHubAgentReleaseResolver {
    private static final String SHA256_PATTERN = "[0-9a-f]{64}";
    private static final String COMMIT_PATTERN = "[0-9a-f]{40}";

    private final ObjectMapper mapper;
    private final AgentReleaseProperties properties;
    private final JdbcTemplate jdbc;
    private final Fetcher fetcher;

    public GitHubAgentReleaseResolver(ObjectMapper mapper, AgentReleaseProperties properties, JdbcTemplate jdbc) {
        this(mapper, properties, jdbc, new HttpFetcher(properties));
    }

    GitHubAgentReleaseResolver(ObjectMapper mapper, AgentReleaseProperties properties, JdbcTemplate jdbc, Fetcher fetcher) {
        this.mapper = mapper;
        this.properties = properties;
        this.jdbc = jdbc;
        this.fetcher = fetcher;
    }

    public ResolvedAgentRelease resolve(ReleaseSourceType sourceType, String requestedRef, String requestedOs, String requestedArch) {
        String ref = requireText(requestedRef, "ref", 256);
        String os = canonical(requireText(requestedOs, "os", 64));
        String arch = canonical(requireText(requestedArch, "arch", 64));

        String sourceCommit = null;
        String releaseTag;
        String expectedVersion = null;
        boolean requirePrerelease = false;

        if (sourceType == ReleaseSourceType.RELEASE) {
            expectedVersion = normalizeVersion(ref);
            releaseTag = properties.releaseTag(expectedVersion);
        } else {
            sourceCommit = resolveCommit(ref);
            releaseTag = properties.developmentTag(sourceCommit);
            requirePrerelease = true;
        }

        JsonNode release = fetchJson(api("/repos/%s/%s/releases/tags/%s".formatted(
                segment(properties.owner()), segment(properties.repository()), segment(releaseTag))),
                "GitHub release " + releaseTag);
        if (release.path("draft").asBoolean(false)) {
            throw new ResolutionException("release is still a draft: " + releaseTag);
        }
        if (requirePrerelease && !release.path("prerelease").asBoolean(false)) {
            throw new ResolutionException("git-ref builds must be published as GitHub prereleases");
        }

        JsonNode manifestAsset = assetByName(release, properties.manifestAsset());
        if (manifestAsset == null) {
            throw new ResolutionException("release manifest asset is missing: " + properties.manifestAsset());
        }
        URI manifestUri = trustedDownloadUri(text(manifestAsset, "browser_download_url", true));
        JsonNode manifest = parseJson(fetcher.getText(manifestUri), "release manifest");

        String version = text(manifest, "version", true);
        String buildId = text(manifest, "build_id", true);
        String gitCommit = canonical(text(manifest, "git_commit", true));
        if (!gitCommit.matches(COMMIT_PATTERN)) {
            throw new ResolutionException("release manifest git_commit must be a full 40-character commit SHA");
        }
        if (expectedVersion != null && !normalizeVersion(version).equals(expectedVersion)) {
            throw new ResolutionException("release manifest version does not match requested version");
        }
        if (sourceCommit != null && !gitCommit.equals(sourceCommit)) {
            throw new ResolutionException("development release manifest commit does not match resolved git ref");
        }
        if (sourceCommit == null) sourceCommit = gitCommit;

        JsonNode artifact = findManifestArtifact(manifest.path("artifacts"), os, arch);
        String artifactName = text(artifact, "name", true);
        String artifactSha256 = normalizeSha256(text(artifact, "sha256", true));
        JsonNode releaseAsset = assetByName(release, artifactName);
        if (releaseAsset == null) {
            throw new ResolutionException("manifest artifact is not present in the GitHub release: " + artifactName);
        }
        String artifactUrl = trustedDownloadUri(text(releaseAsset, "browser_download_url", true)).toString();
        Instant publishedAt = instant(manifest.path("published_at"));
        if (publishedAt == null) publishedAt = instant(release.path("published_at"));

        ResolvedAgentRelease resolved = new ResolvedAgentRelease(
                sourceType, ref, sourceCommit, version, buildId, gitCommit, os, arch,
                artifactName, artifactUrl, artifactSha256, publishedAt);
        persist(resolved);
        return resolved;
    }

    public List<ResolvedAgentRelease> recent(int limit) {
        int bounded = Math.max(1, Math.min(limit, 100));
        return jdbc.query("""
                SELECT source_type,source_ref,source_commit,version,build_id,git_commit,os,arch,
                       artifact_name,artifact_url,artifact_sha256,published_at
                FROM agent_releases
                ORDER BY discovered_at DESC, release_id DESC
                LIMIT ?
                """, (rs, n) -> new ResolvedAgentRelease(
                ReleaseSourceType.valueOf(rs.getString("source_type")), rs.getString("source_ref"),
                rs.getString("source_commit"), rs.getString("version"), rs.getString("build_id"),
                rs.getString("git_commit"), rs.getString("os"), rs.getString("arch"),
                rs.getString("artifact_name"), rs.getString("artifact_url"), rs.getString("artifact_sha256"),
                toInstant(rs.getTimestamp("published_at"))), bounded);
    }

    private String resolveCommit(String ref) {
        JsonNode commit = fetchJson(api("/repos/%s/%s/commits/%s".formatted(
                segment(properties.owner()), segment(properties.repository()), segment(ref))), "Git ref " + ref);
        String sha = canonical(text(commit, "sha", true));
        if (!sha.matches(COMMIT_PATTERN)) throw new ResolutionException("GitHub returned an invalid commit SHA");
        return sha;
    }

    private void persist(ResolvedAgentRelease release) {
        jdbc.update("""
                INSERT INTO agent_releases(
                    source_type,source_ref,source_commit,version,build_id,git_commit,os,arch,
                    artifact_name,artifact_url,artifact_sha256,published_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT (source_type,source_ref,source_commit,os,arch,artifact_sha256)
                DO UPDATE SET version=EXCLUDED.version,build_id=EXCLUDED.build_id,git_commit=EXCLUDED.git_commit,
                              artifact_name=EXCLUDED.artifact_name,artifact_url=EXCLUDED.artifact_url,
                              published_at=EXCLUDED.published_at,discovered_at=now()
                """, release.sourceType().name(), release.sourceRef(), release.sourceCommit(), release.version(),
                release.buildId(), release.gitCommit(), release.os(), release.arch(), release.artifactName(),
                release.artifactUrl(), release.artifactSha256(),
                release.publishedAt() == null ? null : Timestamp.from(release.publishedAt()));
    }

    private JsonNode fetchJson(URI uri, String label) {
        return parseJson(fetcher.getText(uri), label);
    }

    private JsonNode parseJson(String body, String label) {
        try {
            JsonNode node = mapper.readTree(body);
            if (node == null || !node.isObject()) throw new ResolutionException(label + " must be a JSON object");
            return node;
        } catch (ResolutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ResolutionException("invalid JSON returned for " + label, e);
        }
    }

    private static JsonNode findManifestArtifact(JsonNode artifacts, String os, String arch) {
        if (!artifacts.isArray()) throw new ResolutionException("release manifest artifacts must be an array");
        List<JsonNode> matches = new ArrayList<>();
        for (JsonNode candidate : artifacts) {
            if (!candidate.isObject()) continue;
            String candidateOs = canonical(text(candidate, "os", false));
            String candidateArch = canonical(text(candidate, "arch", false));
            if (os.equals(candidateOs) && arch.equals(candidateArch)) matches.add(candidate);
        }
        if (matches.isEmpty()) throw new ResolutionException("release has no artifact for " + os + "/" + arch);
        if (matches.size() > 1) throw new ResolutionException("release manifest has duplicate artifact mappings for " + os + "/" + arch);
        return matches.getFirst();
    }

    private static JsonNode assetByName(JsonNode release, String name) {
        JsonNode assets = release.path("assets");
        if (!assets.isArray()) throw new ResolutionException("GitHub release assets are missing");
        JsonNode match = null;
        for (JsonNode asset : assets) {
            if (name.equals(text(asset, "name", false))) {
                if (match != null) throw new ResolutionException("GitHub release contains duplicate asset name: " + name);
                match = asset;
            }
        }
        return match;
    }

    private URI api(String path) {
        return URI.create(properties.apiBase().replaceAll("/+$", "") + path);
    }

    private static URI trustedDownloadUri(String value) {
        URI uri;
        try { uri = URI.create(value); }
        catch (RuntimeException e) { throw new ResolutionException("release asset URL is invalid", e); }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null ||
                !("github.com".equalsIgnoreCase(uri.getHost()) || uri.getHost().toLowerCase(Locale.ROOT).endsWith(".githubusercontent.com"))) {
            throw new ResolutionException("release asset URL must be an HTTPS GitHub URL");
        }
        return uri;
    }

    private static String normalizeVersion(String value) {
        String trimmed = requireText(value, "version", 128).trim();
        return trimmed.matches("v\\d.*") ? trimmed.substring(1) : trimmed;
    }

    private static String normalizeSha256(String value) {
        String normalized = canonical(value);
        if (normalized.startsWith("sha256:")) normalized = normalized.substring(7);
        if (!normalized.matches(SHA256_PATTERN)) throw new ResolutionException("artifact sha256 is invalid");
        return normalized;
    }

    private static String text(JsonNode node, String field, boolean required) {
        JsonNode value = node == null ? null : node.get(field);
        if (value == null || value.isNull()) {
            if (required) throw new ResolutionException(field + " is required");
            return null;
        }
        if (!value.isTextual() || value.asText().isBlank()) {
            if (required) throw new ResolutionException(field + " must be non-empty text");
            return null;
        }
        return value.asText();
    }

    private static Instant instant(JsonNode node) {
        if (node == null || !node.isTextual() || node.asText().isBlank()) return null;
        try { return Instant.parse(node.asText()); }
        catch (RuntimeException e) { throw new ResolutionException("published_at must be an ISO-8601 instant"); }
    }

    private static String requireText(String value, String field, int maxLength) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
        if (value.length() > maxLength) throw new IllegalArgumentException(field + " is too long");
        return value;
    }

    private static String canonical(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }

    private static String segment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static Instant toInstant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    interface Fetcher {
        String getText(URI uri);
    }

    private static final class HttpFetcher implements Fetcher {
        private final HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        private final AgentReleaseProperties properties;

        private HttpFetcher(AgentReleaseProperties properties) {
            this.properties = properties;
        }

        @Override
        public String getText(URI uri) {
            HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/vnd.github+json")
                    .header("User-Agent", "neta-coordinator")
                    .GET();
            if (!properties.githubToken().isBlank() && "api.github.com".equalsIgnoreCase(uri.getHost())) {
                request.header("Authorization", "Bearer " + properties.githubToken());
                request.header("X-GitHub-Api-Version", "2022-11-28");
            }
            try {
                HttpResponse<String> response = client.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    throw new ResolutionException("GitHub request failed with HTTP " + response.statusCode() + " for " + uri.getPath());
                }
                return response.body();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ResolutionException("GitHub request was interrupted", e);
            } catch (IOException e) {
                throw new ResolutionException("GitHub request failed", e);
            }
        }
    }

    public static final class ResolutionException extends RuntimeException {
        public ResolutionException(String message) { super(message); }
        public ResolutionException(String message, Throwable cause) { super(message, cause); }
    }
}
