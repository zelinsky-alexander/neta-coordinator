package dev.neta.coordinator.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Read-only analyst preview for learned baseline promotion. */
@RestController
@RequestMapping("/api/v1/operator/baselines")
public class BaselineReviewPreviewController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";
    private static final Set<String> CONNECTION_ENGINE_PREFIXES = Set.of(
            "BEH-", "NET-", "DNS-", "TLS-", "ROUTE-");

    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    private final String adminToken;

    public BaselineReviewPreviewController(JdbcTemplate jdbc,
                                           ObjectMapper json,
                                           @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.jdbc = jdbc;
        this.json = json;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @GetMapping("/{candidateId}/preview")
    public BaselinePromotionPreview preview(
            @RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
            @PathVariable long candidateId) {
        requireAdmin(suppliedToken);
        Candidate candidate = candidate(candidateId);
        String engine = currentEngine(candidate.ruleId());
        PreviewDecision decision = decision(candidate, engine);
        return new BaselinePromotionPreview(
                candidate.candidateId(), candidate.agentId(), candidate.endpointName(), candidate.ruleId(), engine,
                candidate.candidateType(), candidate.candidateKey(), candidate.observationCount(),
                candidate.minimumObservations(), candidate.status(), decision.promotable(),
                decision.exclusionsPatch(), decision.explanation());
    }

    private Candidate candidate(long candidateId) {
        List<Candidate> rows = jdbc.query("""
                SELECT c.candidate_id,c.agent_id,a.display_name,c.rule_id,c.candidate_type,c.candidate_key,
                       c.evidence_json::text,c.observation_count,c.status,
                       coalesce(s.minimum_observations,5) AS minimum_observations
                  FROM baseline_candidates c
                  JOIN agents a ON a.agent_id=c.agent_id
                  LEFT JOIN endpoint_learning_state s ON s.agent_id=c.agent_id
                 WHERE c.candidate_id=?
                """, (rs, n) -> new Candidate(
                rs.getLong("candidate_id"), rs.getString("agent_id"), rs.getString("display_name"),
                rs.getString("rule_id"), rs.getString("candidate_type"), rs.getString("candidate_key"),
                parse(rs.getString("evidence_json")), rs.getLong("observation_count"), rs.getString("status"),
                rs.getInt("minimum_observations")), candidateId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "baseline candidate not found");
        return rows.getFirst();
    }

    private String currentEngine(String ruleId) {
        if (ruleId == null || ruleId.isBlank()) return "";
        List<String> engines = jdbc.query("""
                SELECT engine_rule_id FROM rule_definitions
                 WHERE rule_id=? ORDER BY revision DESC LIMIT 1
                """, (rs, n) -> rs.getString(1), ruleId);
        return engines.isEmpty() ? "" : engines.getFirst();
    }

    private PreviewDecision decision(Candidate candidate, String engine) {
        ObjectNode patch = json.createObjectNode();
        if (!"CANDIDATE".equals(candidate.status()))
            return new PreviewDecision(false, patch, "This candidate has already been reviewed.");
        if (candidate.observationCount() < candidate.minimumObservations())
            return new PreviewDecision(false, patch,
                    "Review only — the candidate has not reached the configured minimum observation count.");
        if (candidate.ruleId() == null || candidate.ruleId().isBlank() || engine.isBlank())
            return new PreviewDecision(false, patch,
                    "Review only — the candidate has no current trusted rule evaluator identity.");

        if ("PROCESS_PARENT_CHILD".equals(candidate.candidateType())) {
            if (!"PROC-002".equals(engine))
                return new PreviewDecision(false, patch,
                        "Review only — PROCESS_PARENT_CHILD can currently be promoted only for the PROC-002 shell-parent evaluator.");
            String parentImage = text(candidate.evidence(), "parent_image");
            if (parentImage == null || parentImage.isBlank())
                return new PreviewDecision(false, patch,
                        "Review only — the learned process evidence has no parent image.");
            ArrayNode values = patch.putArray("parent_process_names");
            values.add(basename(parentImage));
            return new PreviewDecision(true, patch,
                    "Approve to add this endpoint-only parent-process exclusion to the effective rule policy.");
        }

        if ("REMOTE_DESTINATION".equals(candidate.candidateType())) {
            boolean supported = CONNECTION_ENGINE_PREFIXES.stream().anyMatch(engine::startsWith);
            if (!supported)
                return new PreviewDecision(false, patch,
                        "Review only — REMOTE_DESTINATION promotion is not supported by this evaluator.");
            String remoteHost = text(candidate.evidence(), "remote_host");
            if (remoteHost == null || remoteHost.isBlank())
                return new PreviewDecision(false, patch,
                        "Review only — the learned destination evidence has no remote host.");
            patch.putArray("remote_hosts").add(remoteHost.trim().toLowerCase(Locale.ROOT));
            return new PreviewDecision(true, patch,
                    "Approve to add this endpoint-only remote-host exclusion to the effective rule policy.");
        }

        return new PreviewDecision(false, patch,
                "Review only — this learned candidate type cannot yet be promoted into policy.");
    }

    private JsonNode parse(String value) {
        try { return json.readTree(value == null || value.isBlank() ? "{}" : value); }
        catch (JsonProcessingException e) { throw new IllegalStateException("stored baseline evidence is invalid JSON", e); }
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

    private void requireAdmin(String suppliedToken) {
        if (adminToken.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "baseline administration is disabled; configure NETA_OPERATOR_ADMIN_TOKEN");
        byte[] expected = adminToken.getBytes(StandardCharsets.UTF_8);
        byte[] supplied = (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, supplied))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
    }

    public record BaselinePromotionPreview(long candidateId, String agentId, String endpointName,
                                           String ruleId, String engineRuleId, String candidateType,
                                           String candidateKey, long observationCount, int minimumObservations,
                                           String status, boolean promotable, JsonNode exclusionsPatch,
                                           String explanation) {}
    private record Candidate(long candidateId, String agentId, String endpointName, String ruleId,
                             String candidateType, String candidateKey, JsonNode evidence,
                             long observationCount, String status, int minimumObservations) {}
    private record PreviewDecision(boolean promotable, JsonNode exclusionsPatch, String explanation) {}
}
