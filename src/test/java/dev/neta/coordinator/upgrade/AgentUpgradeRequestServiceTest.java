package dev.neta.coordinator.upgrade;

import dev.neta.coordinator.release.GitHubAgentReleaseResolver;
import dev.neta.coordinator.release.ReleaseSourceType;
import dev.neta.coordinator.release.ResolvedAgentRelease;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AgentUpgradeRequestServiceTest {
    private JdbcTemplate jdbc;
    private GitHubAgentReleaseResolver releases;
    private AgentUpgradeService upgrades;
    private AgentUpgradeRequestService service;

    @BeforeEach
    void setUp() {
        jdbc = mock(JdbcTemplate.class);
        releases = mock(GitHubAgentReleaseResolver.class);
        upgrades = mock(AgentUpgradeService.class);
        service = new AgentUpgradeRequestService(jdbc, releases, upgrades);
    }

    @Test
    void normalReleaseUsesObservedAgentPlatformAndCreatesRequest() throws Exception {
        stubAgent("agent-1", "AWS-ARM", "ACTIVE", "linux", "arm64");
        ResolvedAgentRelease target = target(ReleaseSourceType.RELEASE, "1.4.0", "linux", "arm64");
        AgentUpgrade created = upgrade(target);
        when(releases.resolve(ReleaseSourceType.RELEASE, "1.4.0", "linux", "arm64")).thenReturn(target);
        when(upgrades.createRequest("agent-1", target)).thenReturn(created);

        AgentUpgrade result = service.request("AWS-ARM", ReleaseSourceType.RELEASE, "1.4.0", false);

        assertEquals(created, result);
        verify(releases).resolve(ReleaseSourceType.RELEASE, "1.4.0", "linux", "arm64");
        verify(upgrades).createRequest("agent-1", target);
    }

    @Test
    void gitRefRequiresExplicitDevelopmentAcknowledgement() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.request("AWS-ARM", ReleaseSourceType.GIT_REF, "feature/test", false));

        assertTrue(ex.getMessage().contains("allowDevelopment=true"));
        verify(releases, never()).resolve(any(), anyString(), anyString(), anyString());
    }

    @Test
    void refusesAgentWithoutCompletePlatformIdentity() throws Exception {
        stubAgent("agent-1", "AWS-ARM", "ACTIVE", "linux", null);

        AgentUpgradeService.UpgradeRequestException ex = assertThrows(
                AgentUpgradeService.UpgradeRequestException.class,
                () -> service.request("AWS-ARM", ReleaseSourceType.RELEASE, "1.4.0", false));

        assertTrue(ex.getMessage().contains("OS/architecture"));
        verify(releases, never()).resolve(any(), anyString(), anyString(), anyString());
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubAgent(String id, String name, String status, String os, String arch) throws Exception {
        doAnswer(invocation -> {
            RowMapper mapper = invocation.getArgument(1);
            ResultSet rs = mock(ResultSet.class);
            when(rs.getString("agent_id")).thenReturn(id);
            when(rs.getString("display_name")).thenReturn(name);
            when(rs.getString("status")).thenReturn(status);
            when(rs.getString("agent_os")).thenReturn(os);
            when(rs.getString("agent_arch")).thenReturn(arch);
            return List.of(mapper.mapRow(rs, 0));
        }).when(jdbc).query(anyString(), any(RowMapper.class), any(Object[].class));
    }

    private static ResolvedAgentRelease target(ReleaseSourceType sourceType, String ref, String os, String arch) {
        String commit = "1".repeat(40);
        return new ResolvedAgentRelease(sourceType, ref, commit, "1.4.0", "20260905.1", commit,
                os, arch, "neta-agent.tar.gz",
                "https://github.com/owner/repo/releases/download/v1.4.0/neta-agent.tar.gz",
                "a".repeat(64), Instant.parse("2026-09-05T06:00:00Z"));
    }

    private static AgentUpgrade upgrade(ResolvedAgentRelease target) {
        return new AgentUpgrade(UUID.randomUUID(), "agent-1", "1.3.2", "old-build", null, null,
                target.sourceType(), target.sourceRef(), target.sourceCommit(),
                target.version(), target.buildId(), target.gitCommit(), target.os(), target.arch(),
                target.artifactName(), target.artifactUrl(), target.artifactSha256(),
                AgentUpgradeStatus.REQUESTED, Instant.now(), null, null, null, null, null, null, null, null, null);
    }
}
