package dev.neta.coordinator.rules;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.neta.coordinator.rules.RuleManagementService.EffectiveRuleSet;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Desired-vs-active convergence state for centrally managed NETA rules.
 *
 * The coordinator never pushes executable commands to an endpoint. AgentHello and
 * Heartbeat responses advertise the desired effective revision/hash and the agent
 * decides locally whether to fetch the existing trusted rule bundle endpoint.
 */
@Service
public class RuleConvergenceService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    private final RuleManagementService rules;

    public RuleConvergenceService(JdbcTemplate jdbc, ObjectMapper json, RuleManagementService rules) {
        this.jdbc = jdbc;
        this.json = json;
        this.rules = rules;
    }

    @Transactional
    public RuleControl controlForAgent(String agentId) {
        EffectiveRuleSet effective = rules.effectiveForAgent(agentId);
        upsertDesired(agentId, effective);
        return jdbc.queryForObject("""
                SELECT desired_revision,desired_sha256,active_revision,active_sha256,status,last_error,
                       refresh_requested_at,last_ack_at,
                       (refresh_requested_at IS NOT NULL AND
                        (last_ack_at IS NULL OR refresh_requested_at > last_ack_at)) AS refresh_requested
                  FROM agent_rule_state WHERE agent_id=?
                """, (rs,n) -> {
            Long activeRevision = rs.getObject("active_revision", Long.class);
            String desiredSha = rs.getString("desired_sha256");
            String activeSha = rs.getString("active_sha256");
            boolean refresh = rs.getBoolean("refresh_requested");
            String status = rs.getString("status");
            boolean fetch = refresh || activeSha == null || desiredSha == null
                    || !desiredSha.equalsIgnoreCase(activeSha) || "APPLY_FAILED".equals(status);
            return new RuleControl(
                    rs.getLong("desired_revision"), desiredSha,
                    activeRevision, activeSha, status, rs.getString("last_error"),
                    refresh, fetch,
                    instant(rs.getTimestamp("refresh_requested_at")),
                    instant(rs.getTimestamp("last_ack_at")));
        }, agentId);
    }

    public List<AgentRuleState> fleetStates() {
        List<String> activeAgents = jdbc.query("SELECT agent_id FROM agents WHERE status='ACTIVE' ORDER BY agent_id",
                (rs,n) -> rs.getString(1));
        for (String agentId : activeAgents) controlForAgent(agentId);
        return jdbc.query("""
                SELECT a.agent_id,a.display_name,a.last_seen_at,
                       s.desired_revision,s.desired_sha256,s.active_revision,s.active_sha256,
                       s.status,s.last_error,s.updated_at,s.refresh_requested_at,s.last_ack_at,
                       (s.refresh_requested_at IS NOT NULL AND
                        (s.last_ack_at IS NULL OR s.refresh_requested_at > s.last_ack_at)) AS refresh_requested
                  FROM agents a
                  LEFT JOIN agent_rule_state s ON s.agent_id=a.agent_id
                 WHERE a.status='ACTIVE'
                 ORDER BY a.display_name,a.agent_id
                """, (rs,n) -> {
            String desiredSha = rs.getString("desired_sha256");
            String activeSha = rs.getString("active_sha256");
            String status = rs.getString("status");
            boolean refresh = rs.getBoolean("refresh_requested");
            boolean fetch = refresh || activeSha == null || desiredSha == null
                    || !desiredSha.equalsIgnoreCase(activeSha) || "APPLY_FAILED".equals(status);
            return new AgentRuleState(
                    rs.getString("agent_id"), rs.getString("display_name"),
                    rs.getObject("desired_revision", Long.class), desiredSha,
                    rs.getObject("active_revision", Long.class), activeSha,
                    status == null ? "UNKNOWN" : status, rs.getString("last_error"),
                    instant(rs.getTimestamp("updated_at")),
                    instant(rs.getTimestamp("refresh_requested_at")),
                    instant(rs.getTimestamp("last_ack_at")),
                    instant(rs.getTimestamp("last_seen_at")), refresh, fetch);
        });
    }

    @Transactional
    public AgentRuleState requestRefresh(String agentId, String actor) {
        Integer count = jdbc.queryForObject("SELECT count(*) FROM agents WHERE agent_id=? AND status='ACTIVE'",
                Integer.class, agentId);
        if (count == null || count != 1) throw new IllegalArgumentException("active endpoint not found: " + agentId);

        EffectiveRuleSet effective = rules.effectiveForAgent(agentId);
        upsertDesired(agentId, effective);
        jdbc.update("""
                UPDATE agent_rule_state
                   SET refresh_requested_at=now(),status='STALE',last_error=NULL,updated_at=now()
                 WHERE agent_id=?
                """, agentId);

        ObjectNode details = json.createObjectNode();
        details.put("actor", actor == null || actor.isBlank() ? "operator" : actor.trim());
        details.put("desired_revision", effective.revision());
        details.put("desired_sha256", effective.sha256());
        jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES ('RULE_REFRESH_REQUESTED',?,?::jsonb)",
                agentId, write(details));

        return fleetStates().stream().filter(s -> agentId.equals(s.agentId())).findFirst()
                .orElseThrow(() -> new IllegalStateException("endpoint rule state disappeared after refresh request"));
    }

    private void upsertDesired(String agentId, EffectiveRuleSet effective) {
        jdbc.update("""
                INSERT INTO agent_rule_state(agent_id,desired_revision,desired_sha256,status,updated_at)
                VALUES (?,?,?,'STALE',now())
                ON CONFLICT(agent_id) DO UPDATE SET
                    desired_revision=EXCLUDED.desired_revision,
                    desired_sha256=EXCLUDED.desired_sha256,
                    status=CASE
                        WHEN agent_rule_state.refresh_requested_at IS NOT NULL
                             AND (agent_rule_state.last_ack_at IS NULL OR
                                  agent_rule_state.refresh_requested_at > agent_rule_state.last_ack_at)
                            THEN 'STALE'
                        WHEN agent_rule_state.active_sha256=EXCLUDED.desired_sha256 THEN 'ACTIVE'
                        ELSE 'STALE'
                    END,
                    last_error=CASE
                        WHEN agent_rule_state.active_sha256=EXCLUDED.desired_sha256 THEN NULL
                        ELSE agent_rule_state.last_error
                    END,
                    updated_at=now()
                """, agentId, effective.revision(), effective.sha256());
    }

    private String write(ObjectNode value) {
        try { return json.writeValueAsString(value); }
        catch (Exception e) { throw new IllegalStateException("cannot serialize rule convergence audit", e); }
    }

    private static Instant instant(java.sql.Timestamp value) {
        return value == null ? null : value.toInstant();
    }

    public record RuleControl(long desiredRevision, String desiredSha256,
                              Long activeRevision, String activeSha256,
                              String status, String lastError,
                              boolean refreshRequested, boolean fetchRequired,
                              Instant refreshRequestedAt, Instant lastAckAt) {}

    public record AgentRuleState(String agentId, String endpointName,
                                 Long desiredRevision, String desiredSha256,
                                 Long activeRevision, String activeSha256,
                                 String status, String lastError,
                                 Instant updatedAt, Instant refreshRequestedAt,
                                 Instant lastAckAt, Instant lastSeenAt,
                                 boolean refreshRequested, boolean fetchRequired) {}
}
