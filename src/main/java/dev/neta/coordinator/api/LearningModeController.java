package dev.neta.coordinator.api;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** RM3.4 endpoint learning lifecycle and review-only baseline candidates. */
@RestController
@RequestMapping("/api/v1/operator/learning")
public class LearningModeController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";
    private final JdbcTemplate jdbc;
    private final String adminToken;

    public LearningModeController(JdbcTemplate jdbc,
                                  @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.jdbc = jdbc;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @GetMapping
    @Transactional
    public LearningOverview overview(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken) {
        requireAdmin(suppliedToken);
        expireLearningWindows();
        List<LearningState> states = jdbc.query("""
                SELECT s.agent_id,a.display_name,s.mode,s.started_at,s.learning_until,s.minimum_observations,s.updated_at,
                       count(c.candidate_id) FILTER (WHERE c.status='CANDIDATE') AS candidate_count,
                       coalesce(max(c.observation_count) FILTER (WHERE c.status='CANDIDATE'),0) AS max_observations
                FROM endpoint_learning_state s
                JOIN agents a ON a.agent_id=s.agent_id
                LEFT JOIN baseline_candidates c ON c.agent_id=s.agent_id
                GROUP BY s.agent_id,a.display_name,s.mode,s.started_at,s.learning_until,s.minimum_observations,s.updated_at
                ORDER BY a.display_name,s.agent_id
                """, (rs, n) -> new LearningState(
                rs.getString("agent_id"), rs.getString("display_name"), apiMode(rs.getString("mode")),
                instant(rs.getTimestamp("started_at")), instant(rs.getTimestamp("learning_until")),
                rs.getInt("minimum_observations"), instant(rs.getTimestamp("updated_at")),
                rs.getLong("candidate_count"), rs.getLong("max_observations")));
        List<BaselineCandidate> candidates = jdbc.query("""
                SELECT c.candidate_id,c.agent_id,a.display_name,c.rule_id,c.candidate_type,c.candidate_key,
                       c.evidence_json::text,c.observation_count,c.first_seen,c.last_seen,c.status,
                       coalesce(s.minimum_observations,5) AS minimum_observations
                FROM baseline_candidates c
                JOIN agents a ON a.agent_id=c.agent_id
                LEFT JOIN endpoint_learning_state s ON s.agent_id=c.agent_id
                WHERE c.status='CANDIDATE'
                ORDER BY c.observation_count DESC,c.last_seen DESC,c.candidate_id DESC
                LIMIT 500
                """, (rs, n) -> new BaselineCandidate(
                rs.getLong("candidate_id"), rs.getString("agent_id"), rs.getString("display_name"),
                rs.getString("rule_id"), rs.getString("candidate_type"), rs.getString("candidate_key"),
                rs.getString("evidence_json"), rs.getLong("observation_count"),
                instant(rs.getTimestamp("first_seen")), instant(rs.getTimestamp("last_seen")),
                rs.getString("status"), rs.getLong("observation_count") >= rs.getInt("minimum_observations")));
        return new LearningOverview(states, candidates);
    }

    @PostMapping("/{agentId}/start")
    @Transactional
    public LearningState start(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                               @PathVariable String agentId,
                               @RequestParam(value = "minimumObservations", defaultValue = "5") int minimumObservations,
                               @RequestParam(value = "hours", defaultValue = "24") int hours) {
        requireAdmin(suppliedToken);
        requireAgent(agentId);
        if (minimumObservations < 2 || minimumObservations > 1000)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "minimumObservations must be between 2 and 1000");
        if (hours < 1 || hours > 24 * 30)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "hours must be between 1 and 720");
        jdbc.update("DELETE FROM baseline_candidates WHERE agent_id=? AND status='CANDIDATE'", agentId);
        jdbc.update("""
                INSERT INTO endpoint_learning_state(agent_id,mode,started_at,learning_until,minimum_observations,updated_at)
                VALUES (?,'LEARNING',now(),now()+(? * interval '1 hour'),?,now())
                ON CONFLICT(agent_id) DO UPDATE SET
                    mode='LEARNING',started_at=now(),learning_until=now()+(? * interval '1 hour'),
                    minimum_observations=EXCLUDED.minimum_observations,updated_at=now()
                """, agentId, hours, minimumObservations, hours);
        audit("LEARNING_STARTED", agentId, "minimum_observations", Integer.toString(minimumObservations));
        return state(agentId);
    }

    @PostMapping("/{agentId}/review")
    @Transactional
    public LearningState review(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                                @PathVariable String agentId) {
        requireAdmin(suppliedToken);
        requireAgent(agentId);
        ensureState(agentId);
        jdbc.update("UPDATE endpoint_learning_state SET mode='REVIEW',updated_at=now() WHERE agent_id=?", agentId);
        audit("LEARNING_REVIEW_REQUESTED", agentId, null, null);
        return state(agentId);
    }

    @PostMapping("/{agentId}/off")
    @Transactional
    public LearningState off(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                             @PathVariable String agentId) {
        requireAdmin(suppliedToken);
        requireAgent(agentId);
        ensureState(agentId);
        jdbc.update("UPDATE endpoint_learning_state SET mode='OFF',learning_until=now(),updated_at=now() WHERE agent_id=?", agentId);
        audit("LEARNING_STOPPED", agentId, null, null);
        return state(agentId);
    }

    private void expireLearningWindows() {
        jdbc.update("""
                UPDATE endpoint_learning_state s SET mode='REVIEW',updated_at=now()
                WHERE mode='LEARNING' AND learning_until IS NOT NULL AND learning_until < now()
                  AND EXISTS (SELECT 1 FROM baseline_candidates c WHERE c.agent_id=s.agent_id AND c.status='CANDIDATE')
                """);
        jdbc.update("""
                UPDATE endpoint_learning_state s SET mode='OFF',updated_at=now()
                WHERE mode='LEARNING' AND learning_until IS NOT NULL AND learning_until < now()
                  AND NOT EXISTS (SELECT 1 FROM baseline_candidates c WHERE c.agent_id=s.agent_id AND c.status='CANDIDATE')
                """);
    }

    private LearningState state(String agentId) {
        return jdbc.query("""
                SELECT s.agent_id,a.display_name,s.mode,s.started_at,s.learning_until,s.minimum_observations,s.updated_at,
                       count(c.candidate_id) FILTER (WHERE c.status='CANDIDATE') AS candidate_count,
                       coalesce(max(c.observation_count) FILTER (WHERE c.status='CANDIDATE'),0) AS max_observations
                FROM endpoint_learning_state s JOIN agents a ON a.agent_id=s.agent_id
                LEFT JOIN baseline_candidates c ON c.agent_id=s.agent_id
                WHERE s.agent_id=?
                GROUP BY s.agent_id,a.display_name,s.mode,s.started_at,s.learning_until,s.minimum_observations,s.updated_at
                """, (rs, n) -> new LearningState(
                rs.getString("agent_id"), rs.getString("display_name"), apiMode(rs.getString("mode")),
                instant(rs.getTimestamp("started_at")), instant(rs.getTimestamp("learning_until")),
                rs.getInt("minimum_observations"), instant(rs.getTimestamp("updated_at")),
                rs.getLong("candidate_count"), rs.getLong("max_observations")), agentId).getFirst();
    }

    private void ensureState(String agentId) {
        jdbc.update("""
                INSERT INTO endpoint_learning_state(agent_id,mode,updated_at) VALUES (?,'OFF',now())
                ON CONFLICT(agent_id) DO NOTHING
                """, agentId);
    }

    private void requireAgent(String agentId) {
        Integer count = jdbc.queryForObject("SELECT count(*) FROM agents WHERE agent_id=?", Integer.class, agentId);
        if (count == null || count == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "agent not found");
    }

    private void audit(String event, String agentId, String key, String value) {
        String details = key == null ? "{}" : "{\"" + key + "\":\"" + value + "\"}";
        jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES (?,?,CAST(? AS jsonb))", event, agentId, details);
    }

    private void requireAdmin(String suppliedToken) {
        if (adminToken.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "learning administration is disabled; configure NETA_OPERATOR_ADMIN_TOKEN");
        byte[] expected = adminToken.getBytes(StandardCharsets.UTF_8);
        byte[] supplied = (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, supplied))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
    }

    private static String apiMode(String mode) {
        return "REVIEW".equals(mode) ? "READY_FOR_REVIEW" : mode;
    }
    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }

    public record LearningOverview(List<LearningState> states, List<BaselineCandidate> candidates) {}
    public record LearningState(String agentId, String endpointName, String mode, Instant startedAt,
                                Instant learningUntil, int minimumObservations, Instant updatedAt,
                                long candidateCount, long maxObservations) {}
    public record BaselineCandidate(long candidateId, String agentId, String endpointName, String ruleId,
                                    String candidateType, String candidateKey, String evidenceJson,
                                    long observationCount, Instant firstSeen, Instant lastSeen,
                                    String status, boolean readyForReview) {}
}
