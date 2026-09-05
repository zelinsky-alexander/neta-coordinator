package dev.neta.coordinator.upgrade;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.protocol.AgentBuildIdentity;
import dev.neta.coordinator.protocol.ProtocolException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AgentUpgradeLifecycleService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public AgentUpgradeLifecycleService(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @Transactional
    public void ingestProgress(String agentId, JsonNode payload) {
        UUID upgradeId = parseUpgradeId(payload);
        AgentUpgradeStatus reported = parseReportedStatus(payload);
        String failureCode = optionalText(payload, "failure_code", 128);
        String failureMessage = optionalText(payload, "failure_message", 1000);
        if (reported == AgentUpgradeStatus.FAILED && (failureCode == null || failureCode.isBlank())) {
            throw ProtocolException.badRequest("UpgradeProgress.failure_code is required for FAILED");
        }

        UpgradeState row = lock(upgradeId);
        if (row == null) throw ProtocolException.conflict("upgrade_id is unknown");
        if (!row.agentId().equals(agentId)) throw ProtocolException.conflict("upgrade does not belong to reporting agent");

        AgentUpgradeStatus current = row.status();
        if (current == reported) return;
        if (isSurpassedNonterminal(current, reported)) return;
        if (!legalProgress(current, reported)) {
            throw ProtocolException.conflict("illegal upgrade state transition: " + current + " -> " + reported);
        }

        String timestampColumn = switch (reported) {
            case DOWNLOADING -> "download_started_at";
            case INSTALLING -> "install_started_at";
            case LOCAL_HEALTHY -> "local_healthy_at";
            case FAILED -> "failed_at";
            case ROLLED_BACK -> "rolled_back_at";
            default -> throw ProtocolException.badRequest("UpgradeProgress.status is not agent-reportable");
        };

        if (reported == AgentUpgradeStatus.FAILED || reported == AgentUpgradeStatus.ROLLED_BACK) {
            jdbc.update("UPDATE agent_upgrades SET status=?, " + timestampColumn + "=COALESCE(" + timestampColumn + ",now()), failure_code=?, failure_message=? WHERE upgrade_id=?",
                    reported.name(), failureCode, failureMessage, upgradeId);
        } else {
            jdbc.update("UPDATE agent_upgrades SET status=?, " + timestampColumn + "=COALESCE(" + timestampColumn + ",now()) WHERE upgrade_id=?",
                    reported.name(), upgradeId);
        }
        audit(agentId, "AGENT_UPGRADE_PROGRESS", Map.of(
                "upgrade_id", upgradeId.toString(),
                "previous_status", current.name(),
                "new_status", reported.name(),
                "failure_code", failureCode == null ? "" : failureCode,
                "failure_message", failureMessage == null ? "" : failureMessage));
    }

    @Transactional
    public void reconcileReportedBuild(String agentId, AgentBuildIdentity build) {
        if (build == null) return;
        List<UpgradeState> rows = jdbc.query("""
                SELECT upgrade_id,agent_id,status,
                       from_version,from_build_id,from_git_commit,from_artifact_sha256,
                       target_version,target_build_id,target_git_commit,target_os,target_arch,artifact_sha256
                FROM agent_upgrades
                WHERE agent_id=? AND status='LOCAL_HEALTHY'
                ORDER BY requested_at DESC
                LIMIT 1
                FOR UPDATE
                """, (rs, n) -> map(rs), agentId);
        if (rows.isEmpty()) return;
        UpgradeState row = rows.getFirst();

        if (matchesTarget(row, build)) {
            jdbc.update("UPDATE agent_upgrades SET status='CONFIRMED', confirmed_at=COALESCE(confirmed_at,now()) WHERE upgrade_id=? AND status='LOCAL_HEALTHY'",
                    row.upgradeId());
            audit(agentId, "AGENT_UPGRADE_CONFIRMED", Map.of(
                    "upgrade_id", row.upgradeId().toString(),
                    "target_version", row.targetVersion(),
                    "target_build_id", row.targetBuildId(),
                    "target_git_commit", row.targetGitCommit(),
                    "artifact_sha256", row.targetArtifactSha256()));
            return;
        }

        if (matchesPrevious(row, build)) {
            jdbc.update("""
                    UPDATE agent_upgrades
                    SET status='ROLLED_BACK', rolled_back_at=COALESCE(rolled_back_at,now()),
                        failure_code=COALESCE(failure_code,'RESTARTED_ON_PREVIOUS_BUILD'),
                        failure_message=COALESCE(failure_message,'Agent reconnected on the pre-upgrade build after local health')
                    WHERE upgrade_id=? AND status='LOCAL_HEALTHY'
                    """, row.upgradeId());
            audit(agentId, "AGENT_UPGRADE_ROLLED_BACK", Map.of(
                    "upgrade_id", row.upgradeId().toString(),
                    "reason", "restarted_on_previous_build"));
        }
    }

    private UpgradeState lock(UUID upgradeId) {
        List<UpgradeState> rows = jdbc.query("""
                SELECT upgrade_id,agent_id,status,
                       from_version,from_build_id,from_git_commit,from_artifact_sha256,
                       target_version,target_build_id,target_git_commit,target_os,target_arch,artifact_sha256
                FROM agent_upgrades WHERE upgrade_id=? FOR UPDATE
                """, (rs, n) -> map(rs), upgradeId);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private static boolean legalProgress(AgentUpgradeStatus current, AgentUpgradeStatus next) {
        if (next == AgentUpgradeStatus.FAILED || next == AgentUpgradeStatus.ROLLED_BACK) {
            return current == AgentUpgradeStatus.DELIVERED || current == AgentUpgradeStatus.DOWNLOADING ||
                    current == AgentUpgradeStatus.INSTALLING || current == AgentUpgradeStatus.LOCAL_HEALTHY;
        }
        return (current == AgentUpgradeStatus.DELIVERED && next == AgentUpgradeStatus.DOWNLOADING) ||
                (current == AgentUpgradeStatus.DOWNLOADING && next == AgentUpgradeStatus.INSTALLING) ||
                (current == AgentUpgradeStatus.INSTALLING && next == AgentUpgradeStatus.LOCAL_HEALTHY);
    }

    private static boolean isSurpassedNonterminal(AgentUpgradeStatus current, AgentUpgradeStatus reported) {
        int currentRank = rank(current);
        int reportedRank = rank(reported);
        return currentRank >= 0 && reportedRank >= 0 && reportedRank < currentRank;
    }

    private static int rank(AgentUpgradeStatus status) {
        return switch (status) {
            case DELIVERED -> 0;
            case DOWNLOADING -> 1;
            case INSTALLING -> 2;
            case LOCAL_HEALTHY -> 3;
            default -> -1;
        };
    }

    private static UUID parseUpgradeId(JsonNode payload) {
        String value = requiredText(payload, "upgrade_id", 64);
        try { return UUID.fromString(value); }
        catch (IllegalArgumentException e) { throw ProtocolException.badRequest("UpgradeProgress.upgrade_id must be a UUID"); }
    }

    private static AgentUpgradeStatus parseReportedStatus(JsonNode payload) {
        String value = requiredText(payload, "status", 64).trim().toUpperCase(Locale.ROOT);
        try {
            AgentUpgradeStatus status = AgentUpgradeStatus.valueOf(value);
            if (status == AgentUpgradeStatus.DOWNLOADING || status == AgentUpgradeStatus.INSTALLING ||
                    status == AgentUpgradeStatus.LOCAL_HEALTHY || status == AgentUpgradeStatus.FAILED ||
                    status == AgentUpgradeStatus.ROLLED_BACK) return status;
        } catch (IllegalArgumentException ignored) {
        }
        throw ProtocolException.badRequest("UpgradeProgress.status must be DOWNLOADING, INSTALLING, LOCAL_HEALTHY, FAILED, or ROLLED_BACK");
    }

    private static String requiredText(JsonNode payload, String field, int max) {
        String value = optionalText(payload, field, max);
        if (value == null || value.isBlank()) throw ProtocolException.badRequest("UpgradeProgress." + field + " is required");
        return value;
    }

    private static String optionalText(JsonNode payload, String field, int max) {
        JsonNode node = payload == null ? null : payload.get(field);
        if (node == null || node.isNull()) return null;
        if (!node.isTextual() || node.asText().isBlank()) throw ProtocolException.badRequest("UpgradeProgress." + field + " must be non-empty text");
        if (node.asText().length() > max) throw ProtocolException.badRequest("UpgradeProgress." + field + " is too long");
        return node.asText();
    }

    private static boolean matchesTarget(UpgradeState row, AgentBuildIdentity build) {
        return eq(row.targetVersion(), build.version()) &&
                eq(row.targetBuildId(), build.buildId()) &&
                eqRequired(row.targetGitCommit(), build.gitCommit()) &&
                eqIgnoreCase(row.targetOs(), build.os()) &&
                eqIgnoreCase(row.targetArch(), build.arch()) &&
                eqRequired(row.targetArtifactSha256(), build.artifactSha256());
    }

    private static boolean matchesPrevious(UpgradeState row, AgentBuildIdentity build) {
        if (row.fromVersion() == null || row.fromBuildId() == null) return false;
        if (!eq(row.fromVersion(), build.version()) || !eq(row.fromBuildId(), build.buildId())) return false;
        if (row.fromGitCommit() != null && !eqRequired(row.fromGitCommit(), build.gitCommit())) return false;
        return row.fromArtifactSha256() == null || eqRequired(row.fromArtifactSha256(), build.artifactSha256());
    }

    private static boolean eq(String expected, String actual) { return expected != null && expected.equals(actual); }
    private static boolean eqIgnoreCase(String expected, String actual) { return expected != null && actual != null && expected.equalsIgnoreCase(actual); }
    private static boolean eqRequired(String expected, String actual) { return expected != null && actual != null && expected.equalsIgnoreCase(actual); }

    private void audit(String agentId, String eventType, Map<String, ?> details) {
        try {
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES (?,?,CAST(? AS jsonb))",
                    eventType, agentId, mapper.writeValueAsString(details));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("upgrade lifecycle audit serialization failed", e);
        }
    }

    private static UpgradeState map(ResultSet rs) throws SQLException {
        return new UpgradeState(
                rs.getObject("upgrade_id", UUID.class), rs.getString("agent_id"),
                AgentUpgradeStatus.valueOf(rs.getString("status")),
                rs.getString("from_version"), rs.getString("from_build_id"),
                rs.getString("from_git_commit"), rs.getString("from_artifact_sha256"),
                rs.getString("target_version"), rs.getString("target_build_id"),
                rs.getString("target_git_commit"), rs.getString("target_os"), rs.getString("target_arch"),
                rs.getString("artifact_sha256"));
    }

    private record UpgradeState(UUID upgradeId, String agentId, AgentUpgradeStatus status,
                                String fromVersion, String fromBuildId, String fromGitCommit, String fromArtifactSha256,
                                String targetVersion, String targetBuildId, String targetGitCommit,
                                String targetOs, String targetArch, String targetArtifactSha256) {}
}
