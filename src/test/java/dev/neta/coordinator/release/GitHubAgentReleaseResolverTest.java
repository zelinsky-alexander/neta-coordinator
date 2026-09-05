package dev.neta.coordinator.release;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.config.AgentReleaseProperties;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class GitHubAgentReleaseResolverTest {
    private static final String COMMIT = "1".repeat(40);
    private static final String OTHER_COMMIT = "2".repeat(40);
    private static final String DIGEST = "a".repeat(64);

    private final ObjectMapper mapper = new ObjectMapper();
    private final AgentReleaseProperties properties = new AgentReleaseProperties(
            "owner", "repo", "https://api.github.com", "v%s", "dev-%s", "release-manifest.json", "");

    @Test
    void resolvesReleaseManifestToExactGitHubAsset() {
        FakeFetcher fetcher = new FakeFetcher();
        fetcher.put("https://api.github.com/repos/owner/repo/releases/tags/v1.4.0", releaseJson("v1.4.0", false, COMMIT));
        fetcher.put(manifestUrl("v1.4.0"), manifestJson("1.4.0", COMMIT));
        GitHubAgentReleaseResolver resolver = resolver(fetcher);

        ResolvedAgentRelease result = resolver.resolve(ReleaseSourceType.RELEASE, "1.4.0", "Linux", "ARM64");

        assertEquals(ReleaseSourceType.RELEASE, result.sourceType());
        assertEquals("1.4.0", result.sourceRef());
        assertEquals(COMMIT, result.sourceCommit());
        assertEquals("1.4.0", result.version());
        assertEquals("20260905.1", result.buildId());
        assertEquals("linux", result.os());
        assertEquals("arm64", result.arch());
        assertEquals(DIGEST, result.artifactSha256());
        assertEquals(artifactUrl("v1.4.0"), result.artifactUrl());
    }

    @Test
    void gitRefIsPinnedToCommitBeforeDevelopmentReleaseResolution() {
        FakeFetcher fetcher = new FakeFetcher();
        fetcher.put("https://api.github.com/repos/owner/repo/commits/feature%2Fupgrade", "{\"sha\":\"" + COMMIT + "\"}");
        fetcher.put("https://api.github.com/repos/owner/repo/releases/tags/dev-" + COMMIT,
                releaseJson("dev-" + COMMIT, true, COMMIT));
        fetcher.put(manifestUrl("dev-" + COMMIT), manifestJson("1.4.0-dev.1", COMMIT));
        GitHubAgentReleaseResolver resolver = resolver(fetcher);

        ResolvedAgentRelease result = resolver.resolve(ReleaseSourceType.GIT_REF, "feature/upgrade", "linux", "arm64");

        assertEquals("feature/upgrade", result.sourceRef());
        assertEquals(COMMIT, result.sourceCommit());
        assertEquals(COMMIT, result.gitCommit());
        assertEquals("1.4.0-dev.1", result.version());
    }

    @Test
    void gitRefRejectsDevelopmentManifestForDifferentCommit() {
        FakeFetcher fetcher = new FakeFetcher();
        fetcher.put("https://api.github.com/repos/owner/repo/commits/main", "{\"sha\":\"" + COMMIT + "\"}");
        fetcher.put("https://api.github.com/repos/owner/repo/releases/tags/dev-" + COMMIT,
                releaseJson("dev-" + COMMIT, true, COMMIT));
        fetcher.put(manifestUrl("dev-" + COMMIT), manifestJson("1.4.0-dev.1", OTHER_COMMIT));
        GitHubAgentReleaseResolver resolver = resolver(fetcher);

        assertThrows(GitHubAgentReleaseResolver.ResolutionException.class,
                () -> resolver.resolve(ReleaseSourceType.GIT_REF, "main", "linux", "arm64"));
    }

    @Test
    void releaseRejectsDuplicatePlatformMapping() {
        FakeFetcher fetcher = new FakeFetcher();
        fetcher.put("https://api.github.com/repos/owner/repo/releases/tags/v1.4.0", releaseJson("v1.4.0", false, COMMIT));
        String duplicateManifest = manifestJson("1.4.0", COMMIT).replace("]}", ",{\"os\":\"linux\",\"arch\":\"arm64\",\"name\":\"other.tar.gz\",\"sha256\":\"" + DIGEST + "\"}]}");
        fetcher.put(manifestUrl("v1.4.0"), duplicateManifest);
        GitHubAgentReleaseResolver resolver = resolver(fetcher);

        assertThrows(GitHubAgentReleaseResolver.ResolutionException.class,
                () -> resolver.resolve(ReleaseSourceType.RELEASE, "1.4.0", "linux", "arm64"));
    }

    private GitHubAgentReleaseResolver resolver(FakeFetcher fetcher) {
        return new GitHubAgentReleaseResolver(mapper, properties, mock(JdbcTemplate.class), fetcher);
    }

    private static String releaseJson(String tag, boolean prerelease, String commit) {
        return """
                {"draft":false,"prerelease":%s,"published_at":"2026-09-05T18:42:11Z","target_commitish":"%s","assets":[
                  {"name":"release-manifest.json","browser_download_url":"%s"},
                  {"name":"neta-agent-1.4.0-linux-arm64.tar.gz","browser_download_url":"%s"}
                ]}
                """.formatted(prerelease, commit, manifestUrl(tag), artifactUrl(tag));
    }

    private static String manifestJson(String version, String commit) {
        return """
                {"version":"%s","build_id":"20260905.1","git_commit":"%s","published_at":"2026-09-05T18:42:11Z",
                 "artifacts":[{"os":"linux","arch":"arm64","name":"neta-agent-1.4.0-linux-arm64.tar.gz","sha256":"%s"}]}
                """.formatted(version, commit, DIGEST);
    }

    private static String manifestUrl(String tag) {
        return "https://github.com/owner/repo/releases/download/" + tag + "/release-manifest.json";
    }

    private static String artifactUrl(String tag) {
        return "https://github.com/owner/repo/releases/download/" + tag + "/neta-agent-1.4.0-linux-arm64.tar.gz";
    }

    private static final class FakeFetcher implements GitHubAgentReleaseResolver.Fetcher {
        private final Map<String, String> responses = new HashMap<>();

        void put(String uri, String body) { responses.put(uri, body); }

        @Override
        public String getText(URI uri) {
            String body = responses.get(uri.toString());
            if (body == null) throw new AssertionError("unexpected URI: " + uri);
            return body;
        }
    }
}
