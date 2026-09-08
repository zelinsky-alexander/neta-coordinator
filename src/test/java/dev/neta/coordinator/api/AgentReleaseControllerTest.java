package dev.neta.coordinator.api;

import dev.neta.coordinator.release.GitHubAgentReleaseResolver;
import dev.neta.coordinator.release.ReleaseSourceType;
import dev.neta.coordinator.release.ResolvedAgentRelease;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AgentReleaseControllerTest {
    @Test
    void cachedLatestUsesNewestPublishedBuildNotFirstCachedRef() {
        GitHubAgentReleaseResolver resolver = mock(GitHubAgentReleaseResolver.class);
        ResolvedAgentRelease oldStable = release(ReleaseSourceType.RELEASE, "0.1.0", "gh-old", "7".repeat(40), "linux", "amd64", "2026-09-01T10:00:00Z");
        ResolvedAgentRelease newestLinux = release(ReleaseSourceType.GIT_REF, "1".repeat(40), "gh-new", "1".repeat(40), "linux", "amd64", "2026-09-08T15:00:00Z");
        ResolvedAgentRelease newestWindows = release(ReleaseSourceType.GIT_REF, "1".repeat(40), "gh-new", "1".repeat(40), "windows", "amd64", "2026-09-08T15:00:00Z");
        when(resolver.recent(100)).thenReturn(List.of(oldStable, newestLinux, newestWindows));

        String table = new AgentReleaseController(resolver).releases(20, null, true, true);

        assertTrue(table.contains("gh-new"));
        assertTrue(table.contains("linux/amd64"));
        assertTrue(table.contains("windows/amd64"));
        assertFalse(table.contains("gh-old"));
    }

    private static ResolvedAgentRelease release(ReleaseSourceType sourceType, String ref, String buildId,
                                                String commit, String os, String arch, String publishedAt) {
        return new ResolvedAgentRelease(sourceType, ref, commit, "0.1.0", buildId, commit, os, arch,
                "artifact-" + os + "-" + arch, "https://example.invalid/artifact", "a".repeat(64), Instant.parse(publishedAt));
    }
}
