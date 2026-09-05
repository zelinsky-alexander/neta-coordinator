package dev.neta.coordinator.upgrade;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.release.ReleaseSourceType;
import dev.neta.coordinator.release.ResolvedAgentRelease;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AgentUpgradeService {
    private static final int MAX_LIST_LIMIT = 100;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public AgentUpgradeService(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @Transactional
    public AgentUpgrade createRequest(String agentId, ResolvedAgentRelease target) {
        if (agentId == null || agentId.isBlank()) throw new IllegalArgumentException("agent id is required");
        if (target == null) throw new IllegalArgumentException("resolved target is required");

        List<ObservedAgent> agents = jdbc.query("""
                SELECT agent_id, status, agent_version, agent_build_id, agent_git_commit,
                       agent_os, agent_arch, agent_artifact_sha256
                FROM agents
                WHERE agent_id=?
                FOR UPDATE
                """, (rs, n) -> mapObservedAgent(rs), agentId);
        if (agents.size() != 1) throw new UpgradeRequestException("agent not found: " + agentId);
        ObservedAgent agent = agents.getFirst();
        if (!"ACTIVE".equals(agent.status())) throw new UpgradeRequestException("agent is not ACTIVE");

        validatePlatform(agent, target);

        Integer active = jdbc.queryForObject("""
                SELECT count(*) FROM agent_upgrades
                WHERE agent_id=? AND status IN ('REQUESTED','DELIVERED','DOWNLOADING','INSTALLING','LOCAL_HEALTHY')
                """, Integer.class, agentId);
        if (active != null && active > 0) throw new UpgradeRequestException("agent already has an active upgrade");

        UUID upgradeId = UUID.randomUUID();
        Instant requestedAt = Instant.now();
        try {
            jdbc.update("""
                    INSERT INTO agent_upgrades(
                        upgrade_id, agent_id,
                        from_version, from_build_id, from_git_commit, from_artifact_sha256,
                        source_type, source_ref, source_commit,
                        target_version, target_build_id, target_git_commit, target_os, target_arch,
                        artifact_name, artifact_url, artifact_sha256, status, requested_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'REQUESTED',?)
                    """,
                    upgradeId, agentId,
                    agent.version(), agent.buildId(), agent.gitCommit(), agent.artifactSha256(),
                    target.sourceType().name(), target.sourceRef(), target.sourceCommit(),
                    target.version(), target.buildId(), target.gitCommit(), target.os(), target.arch(),
                    target.artifactName(), target.artifactUrl(), target.artifactSha256(), Timestamp.from(requestedAt));
        } catch (DuplicateKeyException e) {
            throw new UpgradeRequestException("agent already has an active upgrade", e);
        }

        auditRequested(upgradeId, agent, target);
        return new AgentUpgrade(
                upgradeId, agentId,
                agent.version(), agent.buildId(), agent.gitCommit(), agent.artifactSha256(),
                target.sourceType(), target.sourceRef(), target.sourceCommit(),
                target.version(), target.buildId(), target.gitCommit(), target.os(), target.arch(),
                target.artifactName(), target.artifactUrl(), target.artifactSha256(),
                AgentUpgradeStatus.REQUESTED, requestedAt,
                null, null, null, null, null, null, null, null, null);
    }

    public AgentUpgrade get(UUID upgradeId) {
        if (upgradeId == null) throw new IllegalArgumentException("upgrade id is required");
        List<AgentUpgrade> rows = jdbc.query(selectSql() + " WHERE upgrade_id=?",
                (rs, n) -> mapUpgrade(rs), upgradeId);
        if (rows.isEmpty()) throw new UpgradeRequestException("upgrade not found: " + upgradeId);
        return rows.getFirst();
    }

    public List<AgentUpgrade> recent(String agentId, int limit) {
        int bounded = Math.max(1, Math.min(limit, MAX_LIST_LIMIT));
        if (agentId == null || agentId.isBlank()) {
            return jdbc.query(selectSql() + " ORDER BY requested_at DESC LIMIT ?",
                    (rs, n) -> mapUpgrade(rs), bounded);
        }
        return jdbc.query(selectSql() + " WHERE agent_id=? ORDER BY requested_at DESC LIMIT ?",
                (rs, n) -> mapUpgrade(rs), agentId, bounded);
    }

    private static void validatePlatform(ObservedAgent agent, ResolvedAgentRelease target) {
        if (agent.os() != null && !agent.os().isBlank() && !agent.os().equalsIgnoreCase(target.os())) {
            throw new UpgradeRequestException("resolved target OS does not match observed agent OS");
        }
        if (agent.arch() != null && !agent.arch().isBlank() && !agent.arch().equalsIgnoreCase(target.arch())) {
            throw new UpgradeRequestException("resolved target architecture does not match observed agent architecture");
        }
    }

    private void auditRequested(UUID upgradeId, ObservedAgent agent, ResolvedAgentRelease target) {
        try {
            String details = mapper.writeValueAsString(Map.ofEntries(
                    Map.entry("upgrade_id", upgradeId.toString()),
                    Map.entry("from_version", value(agent.version())),
                    Map.entry("from_build_id", value(agent.buildId())),
                    Map.entry("target_version", target.version()),
                    Map.entry("target_build_id", target.buildId()),
                    Map.entry("target_git_commit", target.gitCommit()),
                    Map.entry("source_type", target.sourceType().name()),
                    Map.entry("source_ref", target.sourceRef()),
                    Map.entry("source_commit", target.sourceCommit()),
                    Map.entry("platform", target.os() + "/" + target.arch()),
                    Map.entry("artifact_sha256", target.artifactSha256())));
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES ('AGENT_UPGRADE_REQUESTED',?,CAST(? AS jsonb))",
                    agent.agentId(), details);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("upgrade audit serialization failed", e);
        }
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }

    private static String selectSql() {
        return """
                SELECT upgrade_id, agent_id,
                       from_version, from_build_id, from_git_commit, from_artifact_sha256,
                       source_type, source_ref, source_commit,
                       target_version, target_build_id, target_git_commit, target_os, target_arch,
                       artifact_name, artifact_url, artifact_sha256, status,
                       requested_at, delivered_at, download_started_at, install_started_at,
                       local_healthy_at, confirmed_at, failed_at, rolled_back_at,
                       failure_code, failure_message
                FROM agent_upgrades
                """;
    }

    private static ObservedAgent mapObservedAgent(ResultSet rs) throws SQLException {
        return new ObservedAgent(
                rs.getString("agent_id"), rs.getString("status"),
                rs.getString("agent_version"), rs.getString("agent_build_id"),
                rs.getString("agent_git_commit"), rs.getString("agent_os"),
                rs.getString("agent_arch"), rs.getString("agent_artifact_sha256"));
    }

    private static AgentUpgrade mapUpgrade(ResultSet rs) throws SQLException {
        return new AgentUpgrade(
                rs.getObject("upgrade_id", UUID.class),
                rs.getString("agent_id"),
                rs.getString("from_version"), rs.getString("from_build_id"),
                rs.getString("from_git_commit"), rs.getString("from_artifact_sha256"),
                ReleaseSourceType.valueOf(rs.getString("source_type")),
                rs.getString("source_ref"), rs.getString("source_commit"),
                rs.getString("target_version"), rs.getString("target_build_id"),
                rs.getString("target_git_commit"), rs.getString("target_os"), rs.getString("target_arch"),
                rs.getString("artifact_name"), rs.getString("artifact_url"), rs.getString("artifact_sha256"),
                AgentUpgradeStatus.valueOf(rs.getString("status")),
                instant(rs.getTimestamp("requested_at")), instant(rs.getTimestamp("delivered_at")),
                instant(rs.getTimestamp("download_started_at")), instant(rs.getTimestamp("install_started_at")),
                instant(rs.getTimestamp("local_healthy_at")), instant(rs.getTimestamp("confirmed_at")),
                instant(rs.getTimestamp("failed_at")), instant(rs.getTimestamp("rolled_back_at")),
                rs.getString("failure_code"), rs.getString("failure_message"));
    }

    private static Instant instant(Timestamp value) {
        return value == null ? null : value.toInstant();
    }

    private record ObservedAgent(String agentId, String status, String version, String buildId,
                                 String gitCommit, String os, String arch, String artifactSha256) {}

    public static class UpgradeRequestException extends RuntimeException {
        public UpgradeRequestException(String message) { super(message); }
        public UpgradeRequestException(String message, Throwable cause) { super(message, cause); }
    }
}
