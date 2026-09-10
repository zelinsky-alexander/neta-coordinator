package dev.neta.coordinator.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.neta.coordinator.rules.RuleManagementService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** RM3.5 explicit analyst review and promotion of learned endpoint baselines. */
@RestController
@RequestMapping("/api/v1/operator/baselines")
public class BaselineReviewController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";
    private static final Set<String> CONNECTION_ENGINE_PREFIXES = Set.of(
            "BEH-", "NET-", "DNS-", "TLS-", "ROUTE-");

    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    private final RuleManagementService rules;
    private final String adminToken;

    public BaselineReviewController(JdbcTemplate jdbc,
                                    ObjectMapper json,
                                    RuleManagementService rules,
                                    @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.jdbc = jdbc;
        this.json = json;
        this.rules = rules;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @PostMapping("/{candidateId}/approve")
    @Transactional
    public BaselineReviewResult approve(
            @RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
            @RequestHeader(value = "X-NETA-Actor", required = false) String actor,
            @PathVariable long candidateId,
            @RequestBody ReviewRequest request) {
        requireAdmin(suppliedToken);
        String reason = requireReason(request == null ? null : request.reason());
        Candidate candidate = candidateForUpdate(candidateId);
        if (!"CANDIDATE".equals(candidate.status()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "baseline candidate is already reviewed");
        if (candidate.observationCount() < candidate.minimumObservations())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "baseline candidate has not reached the configured minimum observation count");
        if (candidate.ruleId() == null || candidate.ruleId().isBlank())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "baseline candidate has no rule identity and cannot be promoted safely");

        String engine = currentEngine(candidate.ruleId());
        ObjectNode exclusions = approvedExclusion(candidate, engine);
        String reviewer = actorValue(actor);

        jdbc.update("""
                UPDATE baseline_candidates
                   SET status='APPROVED',reviewed_at=now(),reviewed_by=?,review_reason=?
                 WHERE candidate_id=? AND status='CANDIDATE'
                """, reviewer, reason, candidateId);

        int inserted = jdbc.update("""
                INSERT INTO rule_overrides(scope_type,scope_id,rule_id,exclusions_patch,status,
                                           reason,created_by,created_at,approved_at,source_baseline_candidate_id)
                VALUES ('ENDPOINT',?,?,?::jsonb,'APPROVED',?,?,now(),now(),?)
                ON CONFLICT (source_baseline_candidate_id) WHERE source_baseline_candidate_id IS NOT NULL DO NOTHING
                """, candidate.agentId(), candidate.ruleId(), write(exclusions),
                "Approved learned baseline: " + reason, reviewer, candidateId);
        if (inserted != 1)
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "baseline candidate already has a promoted policy override");

        RuleManagementService.EffectiveRuleSet effective;
        try {
            effective = rules.effectiveForAgent(candidate.agentId());
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        jdbc.update("""
                INSERT INTO agent_rule_state(agent_id,desired_revision,desired_sha256,status,updated_at)
                VALUES (?,?,?,'STALE',now())
                ON CONFLICT(agent_id) DO UPDATE SET
                    desired_revision=EXCLUDED.desired_revision,
                    desired_sha256=EXCLUDED.desired_sha256,
                    status=CASE WHEN agent_rule_state.active_sha256=EXCLUDED.desired_sha256 THEN 'ACTIVE' ELSE 'STALE' END,
                    last_error=NULL,updated_at=now()
                """, candidate.agentId(), effective.revision(), effective.sha256());

        audit("BASELINE_APPROVED", candidate, reviewer, reason, exclusions, effective.sha256());
        finishReviewIfComplete(candidate.agentId());
        return new BaselineReviewResult(candidateId, candidate.agentId(), candidate.ruleId(), "APPROVED",
                effective.revision(), effective.sha256(), exclusions, reviewer, Instant.now());
    }

    @PostMapping("/{candidateId}/reject")
    @Transactional
    public BaselineReviewResult reject(
            @RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
            @RequestHeader(value = "X-NETA-Actor", required = false) String actor,
            @PathVariable long candidateId,
            @RequestBody ReviewRequest request) {
        requireAdmin(suppliedToken);
        String reason = requireReason(request == null ? null : request.reason());
        Candidate candidate = candidateForUpdate(candidateId);
        if (!"CANDIDATE".equals(candidate.status()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "baseline candidate is already reviewed");
        String reviewer = actorValue(actor);
        jdbc.update("""
                UPDATE baseline_candidates
                   SET status='REJECTED',reviewed_at=now(),reviewed_by=?,review_reason=?
                 WHERE candidate_id=? AND status='CANDIDATE'
                """, reviewer, reason, candidateId);
        audit("BASELINE_REJECTED", candidate, reviewer, reason, json.createObjectNode(), null);
        finishReviewIfComplete(candidate.agentId());
        return new BaselineReviewResult(candidateId, candidate.agentId(), candidate.ruleId(), "REJECTED",
                null, null, json.createObjectNode(), reviewer, Instant.now());
    }

    private Candidate candidateForUpdate(long candidateId) {
        List<Candidate> rows = jdbc.query("""
                SELECT c.candidate_id,c.agent_id,c.rule_id,c.candidate_type,c.candidate_key,
                       c.evidence_json::text,c.observation_count,c.status,
                       coalesce(s.minimum_observations,5) AS minimum_observations
                  FROM baseline_candidates c
                  LEFT JOIN endpoint_learning_state s ON s.agent_id=c.agent_id
                 WHERE c.candidate_id=?
                 FOR UPDATE OF c
                """, (rs, n) -> new Candidate(
                rs.getLong("candidate_id"), rs.getString("agent_id"), rs.getString("rule_id"),
                rs.getString("candidate_type"), rs.getString("candidate_key"), parse(rs.getString("evidence_json")),
                rs.getLong("observation_count"), rs.getString("status"), rs.getInt("minimum_observations")), candidateId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "baseline candidate not found");
        return rows.getFirst();
    }

    private String currentEngine(String ruleId) {
        List<String> engines = jdbc.query("""
                SELECT engine_rule_id FROM rule_definitions
                 WHERE rule_id=? ORDER BY revision DESC LIMIT 1
                """, (rs, n) -> rs.getString(1), ruleId);
        if (engines.isEmpty())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "baseline candidate references a rule that is not in the central catalog");
        return engines.getFirst();
    }

    private ObjectNode approvedExclusion(Candidate candidate, String engine) {
        ObjectNode patch = json.createObjectNode();
        if ("PROCESS_PARENT_CHILD".equals(candidate.candidateType())) {
            if (!"PROC-002".equals(engine))
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "process parent/child baselines are promoted only for the shell-parent evaluator");
            String parentImage = text(candidate.evidence(), "parent_image");
            if (parentImage == null || parentImage.isBlank())
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "process baseline has no parent image and cannot be promoted safely");
            ArrayNode values = patch.putArray("parent_process_names");
            values.add(basename(parentImage));
            return patch;
        }
        if ("REMOTE_DESTINATION".equals(candidate.candidateType())) {
            boolean supported = CONNECTION_ENGINE_PREFIXES.stream().anyMatch(engine::startsWith);
            if (!supported)
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "remote destination baseline is not supported by this rule evaluator");
            String remoteHost = text(candidate.evidence(), "remote_host");
            if (remoteHost == null || remoteHost.isBlank())
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "remote destination baseline has no host and cannot be promoted safely");
            patch.putArray("remote_hosts").add(remoteHost.trim().toLowerCase(Locale.ROOT));
            return patch;
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "unsupported baseline candidate type: " + candidate.candidateType());
    }

    private void finishReviewIfComplete(String agentId) {
        Integer remaining = jdbc.queryForObject(
                "SELECT count(*) FROM baseline_candidates WHERE agent_id=? AND status='CANDIDATE'",
                Integer.class, agentId);
        if (remaining != null && remaining == 0) {
            jdbc.update("UPDATE endpoint_learning_state SET mode='OFF',learning_until=now(),updated_at=now() WHERE agent_id=?",
                    agentId);
        }
    }

    private void audit(String event, Candidate candidate, String actor, String reason,
                       JsonNode exclusions, String desiredSha) {
        ObjectNode details = json.createObjectNode();
        details.put("candidate_id", candidate.candidateId());
        details.put("candidate_type", candidate.candidateType());
        details.put("candidate_key", candidate.candidateKey());
        if (candidate.ruleId() != null) details.put("rule_id", candidate.ruleId());
        details.put("actor", actor);
        details.put("reason", reason);
        details.set("exclusions_patch", exclusions);
        if (desiredSha != null) details.put("desired_sha256", desiredSha);
        jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES (?,?,CAST(? AS jsonb))",
                event, candidate.agentId(), write(details));
    }

    private JsonNode parse(String value) {
        try { return json.readTree(value == null || value.isBlank() ? "{}" : value); }
        catch (JsonProcessingException e) { throw new IllegalStateException("stored baseline evidence is invalid JSON", e); }
    }

    private String write(JsonNode value) {
        try { return json.writeValueAsString(value); }
        catch (JsonProcessingException e) { throw new IllegalArgumentException("baseline review payload cannot be serialized", e); }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }

    private static String basename(String path) {
        String normalized = path.trim().replace('\\', '/').toLowerCase(Locale.ROOT);
        int slash = normalized.lastIndexOf('/');
        return slash >= 0 ? normalized.substring(slash + 1) : normalized;
    }

    private static String requireReason(String reason) {
        String value = reason == null ? "" : reason.trim();
        if (value.isBlank()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason is required");
        if (value.length() > 1000) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason must be at most 1000 characters");
        return value;
    }

    private static String actorValue(String actor) {
        return actor == null || actor.isBlank() ? "operator" : actor.trim();
    }

    private void requireAdmin(String suppliedToken) {
        if (adminToken.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "baseline administration is disabled; configure NETA_OPERATOR_ADMIN_TOKEN");
        byte[] expected = adminToken.getBytes(StandardCharsets.UTF_8);
        byte[] supplied = (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, supplied))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
    }

    public record ReviewRequest(String reason) {}
    public record BaselineReviewResult(long candidateId, String agentId, String ruleId, String status,
                                       Long desiredRevision, String desiredSha256, JsonNode exclusionsPatch,
                                       String reviewedBy, Instant reviewedAt) {}
    private record Candidate(long candidateId, String agentId, String ruleId, String candidateType,
                             String candidateKey, JsonNode evidence, long observationCount,
                             String status, int minimumObservations) {}
}
