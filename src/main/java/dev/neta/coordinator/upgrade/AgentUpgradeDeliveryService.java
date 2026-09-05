package dev.neta.coordinator.upgrade;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AgentUpgradeDeliveryService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public AgentUpgradeDeliveryService(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @Transactional
    public Optional<AgentUpgradeInstruction> instructionFor(String agentId) {
        List<DeliveryRow> rows = jdbc.query("""
                SELECT upgrade_id, status, target_version, target_build_id, target_git_commit,
                       target_os, target_arch, artifact_name, artifact_url, artifact_sha256
                FROM agent_upgrades
                WHERE agent_id=? AND status IN ('REQUESTED','DELIVERED')
                ORDER BY requested_at DESC
                LIMIT 1
                FOR UPDATE
                """, (rs, n) -> map(rs), agentId);
        if (rows.isEmpty()) return Optional.empty();

        DeliveryRow row = rows.getFirst();
        if (row.status() == AgentUpgradeStatus.REQUESTED) {
            int updated = jdbc.update("""
                    UPDATE agent_upgrades
                    SET status='DELIVERED', delivered_at=COALESCE(delivered_at, now())
                    WHERE upgrade_id=? AND status='REQUESTED'
                    """, row.upgradeId());
            if (updated == 1) auditDelivered(agentId, row.upgradeId());
        }

        return Optional.of(new AgentUpgradeInstruction(
                row.upgradeId(), row.version(), row.buildId(), row.gitCommit(), row.os(), row.arch(),
                row.artifactName(), row.artifactUrl(), row.artifactSha256()));
    }

    private void auditDelivered(String agentId, UUID upgradeId) {
        try {
            String details = mapper.writeValueAsString(Map.of("upgrade_id", upgradeId.toString()));
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES ('AGENT_UPGRADE_DELIVERED',?,CAST(? AS jsonb))",
                    agentId, details);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("upgrade delivery audit serialization failed", e);
        }
    }

    private static DeliveryRow map(ResultSet rs) throws SQLException {
        return new DeliveryRow(
                rs.getObject("upgrade_id", UUID.class),
                AgentUpgradeStatus.valueOf(rs.getString("status")),
                rs.getString("target_version"), rs.getString("target_build_id"),
                rs.getString("target_git_commit"), rs.getString("target_os"), rs.getString("target_arch"),
                rs.getString("artifact_name"), rs.getString("artifact_url"), rs.getString("artifact_sha256"));
    }

    private record DeliveryRow(UUID upgradeId, AgentUpgradeStatus status, String version, String buildId,
                               String gitCommit, String os, String arch, String artifactName,
                               String artifactUrl, String artifactSha256) {}
}
