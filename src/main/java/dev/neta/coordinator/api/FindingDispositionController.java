package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.neta.coordinator.incident.IncidentService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/operator")
public class FindingDispositionController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";
    private static final Set<String> TUNING_SCOPES = Set.of("EXACT", "ENDPOINT", "GROUP", "GLOBAL");
    private static final Set<String> TUNING_ACTIONS = Set.of("NONE", "PROPOSE_RULE_EXCLUSION", "PROPOSE_BASELINE");

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final IncidentService incidents;
    private final String adminToken;

    public FindingDispositionController(JdbcTemplate jdbc,
                                        ObjectMapper mapper,
                                        IncidentService incidents,
                                        @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.incidents = incidents;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @PostMapping(value = "/finding-suppress", produces = MediaType.TEXT_PLAIN_VALUE)
    @Transactional
    public String suppress(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                           @RequestParam("id") String findingId,
                           @RequestParam("reason") String reason) {
        return dispose(suppliedToken, findingId, reason, "SUPPRESSED", "FINDING_SUPPRESSED", "EXACT", "NONE");
    }

    @PostMapping(value = "/finding-false-positive", produces = MediaType.TEXT_PLAIN_VALUE)
    @Transactional
    public String falsePositive(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                                @RequestParam("id") String findingId,
                                @RequestParam("reason") String reason,
                                @RequestParam(value = "scope", defaultValue = "EXACT") String scope,
                                @RequestParam(value = "action", defaultValue = "NONE") String action) {
        return dispose(suppliedToken, findingId, reason, "FALSE_POSITIVE", "FINDING_FALSE_POSITIVE",
                normalized(scope, TUNING_SCOPES, "unsupported false-positive scope"),
                normalized(action, TUNING_ACTIONS, "unsupported false-positive tuning action"));
    }

    private String dispose(String suppliedToken, String findingId, String reason,
                           String disposition, String auditEvent, String scope, String action) {
        requireAdmin(suppliedToken);
        requireText(findingId, "finding id is required");
        requireText(reason, "reason is required");
        if (reason.length() > 1000) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason must be at most 1000 characters");
        if ("GROUP".equals(scope) && !"NONE".equals(action)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "group-scoped tuning requires endpoint-group identity support from a later RM3 slice");
        if ("EXACT".equals(scope) && !"NONE".equals(action)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "exact scope is suppression-only; choose endpoint or global scope for a tuning proposal");

        List<FindingRef> rows = jdbc.query("""
                SELECT finding_id,finding_key,agent_id,rule_id,subject_type,subject_id,
                       target_host,target_port,severity,changes::text
                FROM findings WHERE finding_id=?
                """, (rs, n) -> new FindingRef(rs.getString("finding_id"), rs.getString("finding_key"), rs.getString("agent_id"),
                rs.getString("rule_id"), rs.getString("subject_type"), rs.getString("subject_id"), rs.getString("target_host"),
                rs.getObject("target_port", Integer.class), rs.getString("severity"), rs.getString("changes")), findingId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "finding not found");
        FindingRef finding = rows.getFirst();
        List<String> incidentIds = jdbc.query("SELECT incident_id FROM incident_findings WHERE finding_id=?", (rs, n) -> rs.getString(1), finding.findingId());

        Long feedbackId = null;
        if ("FALSE_POSITIVE".equals(disposition)) {
            feedbackId = recordFeedback(finding, reason, scope, action);
            if ("PROPOSE_RULE_EXCLUSION".equals(action)) stageRuleExclusion(finding, reason, scope, feedbackId);
            else if ("PROPOSE_BASELINE".equals(action)) stageBaselineCandidate(finding, feedbackId);
        }

        jdbc.update("""
                INSERT INTO finding_suppressions(agent_id,finding_key,disposition,reason,rule_id,subject_type,subject_id)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT (agent_id,finding_key) DO UPDATE SET disposition=EXCLUDED.disposition,reason=EXCLUDED.reason,
                    rule_id=EXCLUDED.rule_id,subject_type=EXCLUDED.subject_type,subject_id=EXCLUDED.subject_id,created_at=now()
                """, finding.agentId(), finding.findingKey(), disposition, reason,
                canonicalRuleId(finding.ruleId()), finding.subjectType(), finding.subjectId());

        jdbc.update("UPDATE corroboration_requests SET finding_id=NULL WHERE finding_id=?", finding.findingId());
        jdbc.update("DELETE FROM incident_findings WHERE finding_id=?", finding.findingId());
        jdbc.update("DELETE FROM findings WHERE finding_id=?", finding.findingId());
        jdbc.update("DELETE FROM incidents i WHERE NOT EXISTS (SELECT 1 FROM incident_findings m WHERE m.incident_id=i.incident_id)");
        incidents.syncAll();
        audit(auditEvent, finding, reason, disposition, incidentIds, scope, action, feedbackId);
        if (disposition.equals("FALSE_POSITIVE")) {
            String proposal = "NONE".equals(action) ? " No detection-policy change was requested."
                    : " A " + action + " proposal was staged for " + scope + " scope; it is not active policy until explicitly approved/published.";
            return "Marked finding " + finding.findingId() + " as FALSE_POSITIVE, retained RM3 analyst feedback, and removed it from active coordinator findings." + proposal + "\n";
        }
        return "Suppressed finding " + finding.findingId() + " and removed it from active coordinator findings.\n";
    }

    private long recordFeedback(FindingRef finding, String reason, String scope, String action) {
        ObjectNode context = mapper.createObjectNode();
        if (finding.targetHost() != null) context.put("target_host", finding.targetHost());
        if (finding.targetPort() != null) context.put("target_port", finding.targetPort());
        if (finding.severity() != null) context.put("severity", finding.severity());
        String processImage = changeValue(finding.changes(), "Process image:");
        String parentImage = changeValue(finding.changes(), "Parent image:");
        if (processImage != null) context.put("process_image", processImage);
        if (parentImage != null) context.put("parent_image", parentImage);
        String canonicalRule = canonicalRuleId(finding.ruleId());
        Long id = jdbc.queryForObject("""
                INSERT INTO finding_feedback(finding_id_snapshot,agent_id,finding_key,rule_id,subject_type,subject_id,
                                             feedback_type,requested_scope,requested_action,reason,context_json)
                VALUES (?,?,?,?,?,?,'FALSE_POSITIVE',?,?,?,?::jsonb) RETURNING feedback_id
                """, Long.class, finding.findingId(), finding.agentId(), finding.findingKey(), canonicalRule,
                finding.subjectType(), finding.subjectId(), scope, action, reason, write(context));
        if (id == null) throw new IllegalStateException("failed to persist false-positive feedback");
        return id;
    }

    private void stageRuleExclusion(FindingRef finding, String reason, String scope, long feedbackId) {
        String canonicalRule = canonicalRuleId(finding.ruleId());
        if (canonicalRule == null || canonicalRule.isBlank()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "finding does not expose a rule id that can be tuned");
        ObjectNode patch = mapper.createObjectNode();
        if ("PROC-002".equals(canonicalRule)) {
            String parent = leaf(changeValue(finding.changes(), "Parent image:"));
            if (parent == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "shell-parent exclusion proposal requires Parent image evidence");
            patch.putArray("parent_process_names").add(parent);
        } else {
            String process = leaf(changeValue(finding.changes(), "Process image:"));
            if (process != null) patch.putArray("process_names").add(process);
            else if (finding.targetHost() != null && !finding.targetHost().isBlank()) patch.putArray("remote_hosts").add(finding.targetHost());
            else throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "this finding does not expose a safe minimal exclusion candidate yet");
        }
        String scopeType = "GLOBAL".equals(scope) ? "GLOBAL" : "ENDPOINT";
        String scopeId = "GLOBAL".equals(scope) ? null : finding.agentId();
        jdbc.update("""
                INSERT INTO rule_overrides(scope_type,scope_id,rule_id,exclusions_patch,status,source_feedback_id,reason)
                VALUES (?,?,?,?::jsonb,'STAGED',?,?)
                """, scopeType, scopeId, canonicalRule, write(patch), feedbackId, reason);
    }

    private void stageBaselineCandidate(FindingRef finding, long feedbackId) {
        if (!"PROCESS".equalsIgnoreCase(finding.subjectType())) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "baseline proposal is currently implemented for process findings only");
        String process = changeValue(finding.changes(), "Process image:");
        String parent = changeValue(finding.changes(), "Parent image:");
        if (process == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "process baseline proposal requires Process image evidence");
        ObjectNode evidence = mapper.createObjectNode();
        evidence.put("source_feedback_id", feedbackId); evidence.put("process_image", process); if (parent != null) evidence.put("parent_image", parent);
        String key = (parent == null ? "" : parent) + "->" + process;
        jdbc.update("""
                INSERT INTO baseline_candidates(agent_id,rule_id,candidate_type,candidate_key,evidence_json)
                VALUES (?,?, 'PROCESS_PARENT_CHILD', ?, ?::jsonb)
                ON CONFLICT(agent_id,candidate_type,candidate_key) DO UPDATE SET observation_count=baseline_candidates.observation_count+1,
                    last_seen=now(), evidence_json=EXCLUDED.evidence_json
                """, finding.agentId(), canonicalRuleId(finding.ruleId()), key, write(evidence));
    }

    private void audit(String eventType, FindingRef finding, String reason, String disposition, List<String> incidentIds,
                       String scope, String action, Long feedbackId) {
        try {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("finding_id", finding.findingId()); details.put("finding_key", finding.findingKey());
            details.put("disposition", disposition); details.put("reason", reason); details.put("requested_scope", scope); details.put("requested_action", action);
            if (feedbackId != null) details.put("feedback_id", feedbackId);
            if (finding.ruleId() != null) details.put("rule_id", canonicalRuleId(finding.ruleId()));
            if (finding.subjectType() != null) details.put("subject_type", finding.subjectType());
            if (finding.subjectId() != null) details.put("subject_id", finding.subjectId());
            if (finding.targetHost() != null) details.put("target_host", finding.targetHost());
            if (finding.targetPort() != null) details.put("target_port", finding.targetPort());
            if (finding.severity() != null) details.put("severity", finding.severity());
            if (!incidentIds.isEmpty()) details.put("former_incidents", incidentIds);
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES (?,?,CAST(? AS jsonb))",
                    eventType, finding.agentId(), mapper.writeValueAsString(details));
        } catch (Exception e) { throw new IllegalStateException("failed to record finding disposition audit event", e); }
    }

    private String changeValue(String changes, String prefix) {
        if (changes == null || changes.isBlank()) return null;
        try {
            JsonNode root = mapper.readTree(changes);
            if (!root.isArray()) return null;
            for (JsonNode item : root) if (item.isTextual()) {
                String value = item.asText();
                if (value.regionMatches(true, 0, prefix, 0, prefix.length())) {
                    String extracted = value.substring(prefix.length()).trim(); return extracted.isBlank() ? null : extracted;
                }
            }
        } catch (Exception ignored) { }
        return null;
    }

    private static String leaf(String path) {
        if (path == null || path.isBlank()) return null;
        String normalized = path.replace('\\', '/').toLowerCase(Locale.ROOT);
        int slash = normalized.lastIndexOf('/'); String value = slash >= 0 ? normalized.substring(slash + 1) : normalized;
        return value.isBlank() ? null : value;
    }

    private static String canonicalRuleId(String ruleId) {
        if (ruleId == null || ruleId.isBlank()) return ruleId;
        String shortId = ruleId.startsWith("NETA-") ? ruleId.substring(5) : ruleId;
        if (shortId.startsWith("CUS-")) shortId = "CST-" + shortId.substring(4);
        return switch (shortId) {
            case "PROCESS_EXEC_FROM_TRANSIENT_PATH" -> "PROC-001";
            case "PROCESS_SHELL_FROM_UNEXPECTED_PARENT" -> "PROC-002";
            case "PROCESS_UNEXPECTED_ELEVATION" -> "PROC-003";
            case "PROCESS_RAPID_CHILD_FANOUT" -> "PROC-004";
            case "PROCESS_SHORT_LIVED_BURST" -> "PROC-005";
            default -> shortId;
        };
    }

    private String write(JsonNode value) { try { return mapper.writeValueAsString(value); } catch (Exception e) { throw new IllegalStateException("failed to serialize tuning context", e); } }
    private static String normalized(String value, Set<String> supported, String message) {
        String result = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if (!supported.contains(result)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message); return result;
    }
    private void requireAdmin(String suppliedToken) {
        if (adminToken.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "finding administration is disabled; configure NETA_OPERATOR_ADMIN_TOKEN");
        byte[] expected = adminToken.getBytes(StandardCharsets.UTF_8); byte[] supplied = (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, supplied)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
    }
    private static void requireText(String value, String message) { if (value == null || value.isBlank()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message); }

    private record FindingRef(String findingId, String findingKey, String agentId, String ruleId, String subjectType, String subjectId,
                              String targetHost, Integer targetPort, String severity, String changes) {}
}
