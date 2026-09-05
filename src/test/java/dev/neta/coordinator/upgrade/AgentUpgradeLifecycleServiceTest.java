package dev.neta.coordinator.upgrade;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import dev.neta.coordinator.protocol.AgentBuildIdentity;
import dev.neta.coordinator.protocol.ProtocolException;
import java.sql.ResultSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AgentUpgradeLifecycleServiceTest {
    private static final UUID UPGRADE_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final String OLD_COMMIT = "0".repeat(40);
    private static final String NEW_COMMIT = "1".repeat(40);
    private static final String OLD_SHA = "b".repeat(64);
    private static final String NEW_SHA = "a".repeat(64);

    private JdbcTemplate jdbc;
    private AgentUpgradeLifecycleService service;
    private AtomicReference<AgentUpgradeStatus> status;

    @BeforeEach
    void setUp() throws Exception {
        jdbc = mock(JdbcTemplate.class);
        service = new AgentUpgradeLifecycleService(jdbc, new ObjectMapper());
        status = new AtomicReference<>(AgentUpgradeStatus.DELIVERED);
        stubUpgradeRow("AGENT-1");
        when(jdbc.update(anyString(), any(Object[].class))).thenReturn(1);
    }

    @Test
    void acceptsOrderedProgressAndIsIdempotentForSameState() {
        var payload = JsonNodeFactory.instance.objectNode()
                .put("upgrade_id", UPGRADE_ID.toString())
                .put("status", "DOWNLOADING");

        service.ingestProgress("AGENT-1", payload);
        status.set(AgentUpgradeStatus.DOWNLOADING);
        assertDoesNotThrow(() -> service.ingestProgress("AGENT-1", payload));

        verify(jdbc).update(contains("download_started_at"), any(Object[].class));
    }

    @Test
    void treatsAlreadySurpassedProgressAsRetryNoOp() {
        status.set(AgentUpgradeStatus.INSTALLING);
        var payload = JsonNodeFactory.instance.objectNode()
                .put("upgrade_id", UPGRADE_ID.toString())
                .put("status", "DOWNLOADING");

        assertDoesNotThrow(() -> service.ingestProgress("AGENT-1", payload));
        verify(jdbc, never()).update(contains("download_started_at"), any(Object[].class));
    }

    @Test
    void rejectsForwardSkipAndForeignAgent() {
        var localHealthy = JsonNodeFactory.instance.objectNode()
                .put("upgrade_id", UPGRADE_ID.toString())
                .put("status", "LOCAL_HEALTHY");
        assertThrows(ProtocolException.class, () -> service.ingestProgress("AGENT-1", localHealthy));

        var downloading = JsonNodeFactory.instance.objectNode()
                .put("upgrade_id", UPGRADE_ID.toString())
                .put("status", "DOWNLOADING");
        assertThrows(ProtocolException.class, () -> service.ingestProgress("AGENT-OTHER", downloading));
    }

    @Test
    void failedRequiresFailureCode() {
        var failed = JsonNodeFactory.instance.objectNode()
                .put("upgrade_id", UPGRADE_ID.toString())
                .put("status", "FAILED");
        assertThrows(ProtocolException.class, () -> service.ingestProgress("AGENT-1", failed));
    }

    @Test
    void confirmsOnlyExactTargetBuildAfterLocalHealth() {
        status.set(AgentUpgradeStatus.LOCAL_HEALTHY);
        AgentBuildIdentity exact = build("1.4.0", "20260905.1", NEW_COMMIT, "linux", "arm64", NEW_SHA);

        service.reconcileReportedBuild("AGENT-1", exact);

        verify(jdbc).update(contains("status='CONFIRMED'"), any(Object[].class));
        verify(jdbc).update(contains("INSERT INTO audit_events"), eq("AGENT_UPGRADE_CONFIRMED"), eq("AGENT-1"), anyString());
    }

    @Test
    void doesNotConfirmWhenArtifactIdentityIsMissing() {
        status.set(AgentUpgradeStatus.LOCAL_HEALTHY);
        AgentBuildIdentity incomplete = build("1.4.0", "20260905.1", NEW_COMMIT, "linux", "arm64", null);

        service.reconcileReportedBuild("AGENT-1", incomplete);

        verify(jdbc, never()).update(contains("status='CONFIRMED'"), any(Object[].class));
    }

    @Test
    void recognizesReconnectOnPreviousBuildAsRollback() {
        status.set(AgentUpgradeStatus.LOCAL_HEALTHY);
        AgentBuildIdentity previous = build("1.3.2", "20260831.2", OLD_COMMIT, "linux", "arm64", OLD_SHA);

        service.reconcileReportedBuild("AGENT-1", previous);

        verify(jdbc).update(contains("status='ROLLED_BACK'"), any(Object[].class));
        verify(jdbc).update(contains("INSERT INTO audit_events"), eq("AGENT_UPGRADE_ROLLED_BACK"), eq("AGENT-1"), anyString());
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubUpgradeRow(String ownerAgent) throws Exception {
        doAnswer(invocation -> {
            RowMapper mapper = invocation.getArgument(1);
            ResultSet rs = mock(ResultSet.class);
            when(rs.getObject("upgrade_id", UUID.class)).thenReturn(UPGRADE_ID);
            when(rs.getString("agent_id")).thenReturn(ownerAgent);
            when(rs.getString("status")).thenAnswer(ignored -> status.get().name());
            when(rs.getString("from_version")).thenReturn("1.3.2");
            when(rs.getString("from_build_id")).thenReturn("20260831.2");
            when(rs.getString("from_git_commit")).thenReturn(OLD_COMMIT);
            when(rs.getString("from_artifact_sha256")).thenReturn(OLD_SHA);
            when(rs.getString("target_version")).thenReturn("1.4.0");
            when(rs.getString("target_build_id")).thenReturn("20260905.1");
            when(rs.getString("target_git_commit")).thenReturn(NEW_COMMIT);
            when(rs.getString("target_os")).thenReturn("linux");
            when(rs.getString("target_arch")).thenReturn("arm64");
            when(rs.getString("artifact_sha256")).thenReturn(NEW_SHA);
            return List.of(mapper.mapRow(rs, 0));
        }).when(jdbc).query(anyString(), any(RowMapper.class), any(Object[].class));
    }

    private static AgentBuildIdentity build(String version, String buildId, String commit,
                                            String os, String arch, String sha) {
        return new AgentBuildIdentity(version, buildId, commit, os, arch, sha, 1, 1,
                JsonNodeFactory.instance.arrayNode());
    }
}
