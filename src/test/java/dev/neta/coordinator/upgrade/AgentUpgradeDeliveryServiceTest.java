package dev.neta.coordinator.upgrade;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.ResultSet;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AgentUpgradeDeliveryServiceTest {
    private static final UUID UPGRADE_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final String COMMIT = "1".repeat(40);
    private static final String SHA = "a".repeat(64);

    @Test
    void firstDeliveryTransitionsRequestedAndReturnsTypedInstruction() throws Exception {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        stubDeliveryRow(jdbc, AgentUpgradeStatus.REQUESTED);
        when(jdbc.update(anyString(), any(Object[].class))).thenReturn(1);
        AgentUpgradeDeliveryService service = new AgentUpgradeDeliveryService(jdbc, new ObjectMapper());

        AgentUpgradeInstruction instruction = service.instructionFor("AGENT-1").orElseThrow();

        assertEquals(UPGRADE_ID, instruction.upgradeId());
        assertEquals("1.4.0", instruction.version());
        assertEquals("20260905.1", instruction.buildId());
        assertEquals(COMMIT, instruction.gitCommit());
        assertEquals("linux", instruction.os());
        assertEquals("arm64", instruction.arch());
        assertEquals(SHA, instruction.sha256());
        verify(jdbc).update(org.mockito.ArgumentMatchers.contains("status='DELIVERED'"), any(Object[].class));
        verify(jdbc).update(org.mockito.ArgumentMatchers.contains("AGENT_UPGRADE_DELIVERED"), any(Object[].class));
    }

    @Test
    void deliveredInstructionIsRepeatedWithoutAnotherTransitionOrAudit() throws Exception {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        stubDeliveryRow(jdbc, AgentUpgradeStatus.DELIVERED);
        AgentUpgradeDeliveryService service = new AgentUpgradeDeliveryService(jdbc, new ObjectMapper());

        assertTrue(service.instructionFor("AGENT-1").isPresent());

        verify(jdbc, never()).update(org.mockito.ArgumentMatchers.contains("status='DELIVERED'"), any(Object[].class));
        verify(jdbc, never()).update(org.mockito.ArgumentMatchers.contains("AGENT_UPGRADE_DELIVERED"), any(Object[].class));
    }

    @Test
    void noPendingUpgradeReturnsNoInstruction() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.query(anyString(), any(RowMapper.class), any(Object[].class))).thenReturn(List.of());
        AgentUpgradeDeliveryService service = new AgentUpgradeDeliveryService(jdbc, new ObjectMapper());

        assertFalse(service.instructionFor("AGENT-1").isPresent());
    }

    @Test
    void instructionSerializesWithStableWireFieldNames() throws Exception {
        AgentUpgradeInstruction instruction = new AgentUpgradeInstruction(
                UPGRADE_ID, "1.4.0", "20260905.1", COMMIT, "linux", "arm64",
                "neta-agent-1.4.0-linux-arm64.tar.gz",
                "https://github.com/owner/repo/releases/download/v1.4.0/neta-agent.tar.gz", SHA);

        var json = new ObjectMapper().readTree(new ObjectMapper().writeValueAsString(instruction));
        assertEquals(UPGRADE_ID.toString(), json.path("upgrade_id").asText());
        assertEquals("20260905.1", json.path("build_id").asText());
        assertEquals(COMMIT, json.path("git_commit").asText());
        assertEquals("neta-agent-1.4.0-linux-arm64.tar.gz", json.path("artifact_name").asText());
        assertEquals("https://github.com/owner/repo/releases/download/v1.4.0/neta-agent.tar.gz",
                json.path("download_url").asText());
        assertEquals(SHA, json.path("sha256").asText());
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static void stubDeliveryRow(JdbcTemplate jdbc, AgentUpgradeStatus status) throws Exception {
        doAnswer(invocation -> {
            RowMapper mapper = invocation.getArgument(1);
            ResultSet rs = mock(ResultSet.class);
            when(rs.getObject("upgrade_id", UUID.class)).thenReturn(UPGRADE_ID);
            when(rs.getString("status")).thenReturn(status.name());
            when(rs.getString("target_version")).thenReturn("1.4.0");
            when(rs.getString("target_build_id")).thenReturn("20260905.1");
            when(rs.getString("target_git_commit")).thenReturn(COMMIT);
            when(rs.getString("target_os")).thenReturn("linux");
            when(rs.getString("target_arch")).thenReturn("arm64");
            when(rs.getString("artifact_name")).thenReturn("neta-agent-1.4.0-linux-arm64.tar.gz");
            when(rs.getString("artifact_url")).thenReturn("https://github.com/owner/repo/releases/download/v1.4.0/neta-agent.tar.gz");
            when(rs.getString("artifact_sha256")).thenReturn(SHA);
            return List.of(mapper.mapRow(rs, 0));
        }).when(jdbc).query(anyString(), any(RowMapper.class), any(Object[].class));
    }
}
