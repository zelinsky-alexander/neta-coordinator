package dev.neta.coordinator.upgrade;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.release.ReleaseSourceType;
import dev.neta.coordinator.release.ResolvedAgentRelease;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AgentUpgradeServiceTest {
    private static final String OLD_SHA = "b".repeat(64);
    private static final String NEW_SHA = "a".repeat(64);
    private static final String COMMIT = "1".repeat(40);

    private JdbcTemplate jdbc;
    private AgentUpgradeService service;

    @BeforeEach
    void setUp() throws Exception {
        jdbc = mock(JdbcTemplate.class);
        service = new AgentUpgradeService(jdbc, new ObjectMapper());
        stubObservedAgent("ACTIVE", "1.3.2", "20260831.2", "linux", "arm64");
        when(jdbc.queryForObject(anyString(), eq(Integer.class), any())).thenReturn(0);
        when(jdbc.update(anyString(), any(Object[].class))).thenReturn(1);
    }

    @Test
    void createsImmutableRequestedSnapshotFromObservedAndResolvedState() {
        ResolvedAgentRelease target = target("linux", "arm64");

        AgentUpgrade upgrade = service.createRequest("AGENT-1", target);

        assertEquals("AGENT-1", upgrade.agentId());
        assertEquals("1.3.2", upgrade.fromVersion());
        assertEquals("20260831.2", upgrade.fromBuildId());
        assertEquals(OLD_SHA, upgrade.fromArtifactSha256());
        assertEquals("1.4.0", upgrade.targetVersion());
        assertEquals("20260905.1", upgrade.targetBuildId());
        assertEquals(NEW_SHA, upgrade.artifactSha256());
        assertEquals(AgentUpgradeStatus.REQUESTED, upgrade.status());
        assertTrue(upgrade.requestedAt() != null);
        verify(jdbc).update(org.mockito.ArgumentMatchers.contains("INSERT INTO agent_upgrades"), any(Object[].class));
        verify(jdbc).update(org.mockito.ArgumentMatchers.contains("AGENT_UPGRADE_REQUESTED"), any(Object[].class));
    }

    @Test
    void rejectsSecondActiveUpgradeBeforeInsert() {
        when(jdbc.queryForObject(anyString(), eq(Integer.class), any())).thenReturn(1);

        AgentUpgradeService.UpgradeRequestException ex = assertThrows(
                AgentUpgradeService.UpgradeRequestException.class,
                () -> service.createRequest("AGENT-1", target("linux", "arm64")));

        assertTrue(ex.getMessage().contains("active upgrade"));
        verify(jdbc, never()).update(org.mockito.ArgumentMatchers.contains("INSERT INTO agent_upgrades"), any(Object[].class));
    }

    @Test
    void rejectsResolvedArtifactForDifferentArchitecture() {
        AgentUpgradeService.UpgradeRequestException ex = assertThrows(
                AgentUpgradeService.UpgradeRequestException.class,
                () -> service.createRequest("AGENT-1", target("linux", "amd64")));

        assertTrue(ex.getMessage().contains("architecture"));
        verify(jdbc, never()).update(org.mockito.ArgumentMatchers.contains("INSERT INTO agent_upgrades"), any(Object[].class));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubObservedAgent(String status, String version, String buildId, String os, String arch) throws Exception {
        doAnswer(invocation -> {
            RowMapper mapper = invocation.getArgument(1);
            ResultSet rs = mock(ResultSet.class);
            when(rs.getString("agent_id")).thenReturn("AGENT-1");
            when(rs.getString("status")).thenReturn(status);
            when(rs.getString("agent_version")).thenReturn(version);
            when(rs.getString("agent_build_id")).thenReturn(buildId);
            when(rs.getString("agent_git_commit")).thenReturn("0".repeat(40));
            when(rs.getString("agent_os")).thenReturn(os);
            when(rs.getString("agent_arch")).thenReturn(arch);
            when(rs.getString("agent_artifact_sha256")).thenReturn(OLD_SHA);
            return List.of(mapper.mapRow(rs, 0));
        }).when(jdbc).query(anyString(), any(RowMapper.class), any(Object[].class));
    }

    private static ResolvedAgentRelease target(String os, String arch) {
        return new ResolvedAgentRelease(
                ReleaseSourceType.RELEASE,
                "1.4.0",
                COMMIT,
                "1.4.0",
                "20260905.1",
                COMMIT,
                os,
                arch,
                "neta-agent-1.4.0-linux-arm64.tar.gz",
                "https://github.com/owner/repo/releases/download/v1.4.0/neta-agent.tar.gz",
                NEW_SHA,
                Instant.parse("2026-09-05T06:00:00Z"));
    }
}
