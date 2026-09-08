package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.incident.IncidentService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
        return dispose(suppliedToken, findingId, reason, "SUPPRESSED", "FINDING_SUPPRESSED");
    }

    @PostMapping(value = "/finding-false-positive", produces = MediaType.TEXT_PLAIN_VALUE)
    @Transactional
    public String falsePositive(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                                @RequestParam("id") String findingId,
                                @RequestParam("reason") String reason) {
        return dispose(suppliedToken, findingId, reason, "FALSE_POSITIVE", "FINDING_FALSE_POSITIVE");
    }

    private String dispose(String suppliedToken, String findingId, String reason,
                           String disposition, String auditEvent) {
        requireAdmin(suppliedToken);
        requireText(findingId, "finding id is required");
        requireText(reason, "reason is required");
        if (reason.length() > 1000) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason must be at most 1000 characters");
        }

        List<FindingRef> rows = jdbc.query("""
                SELECT finding_id,finding_key,agent_id,rule_id,subject_type,subject_id,
                       target_host,target_port,severity
                FROM findings WHERE finding_id=?
                """, (rs, n) -> new FindingRef(
                rs.getString("finding_id"), rs.getString("finding_key"), rs.getString("agent_id"),
                rs.getString("rule_id"), rs.getString("subject_type"), rs.getString("subject_id"),
                rs.getString("target_host"), rs.getObject("target_port", Integer.class), rs.getString("severity")),
                findingId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "finding not found");
        FindingRef finding = rows.getFirst();

        List<String> incidentIds = jdbc.query(
                "SELECT incident_id FROM incident_findings WHERE finding_id=?",
                (rs, n) -> rs.getString(1), finding.findingId());

        jdbc.update("""
                INSERT INTO finding_suppressions(agent_id,finding_key,disposition,reason,rule_id,subject_type,subject_id)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT (agent_id,finding_key) DO UPDATE SET
                    disposition=EXCLUDED.disposition,
                    reason=EXCLUDED.reason,
                    rule_id=EXCLUDED.rule_id,
                    subject_type=EXCLUDED.subject_type,
                    subject_id=EXCLUDED.subject_id,
                    created_at=now()
                """, finding.agentId(), finding.findingKey(), disposition, reason,
                finding.ruleId(), finding.subjectType(), finding.subjectId());

        jdbc.update("DELETE FROM incident_findings WHERE finding_id=?", finding.findingId());
        jdbc.update("DELETE FROM findings WHERE finding_id=?", finding.findingId());
        jdbc.update("DELETE FROM incidents i WHERE NOT EXISTS (SELECT 1 FROM incident_findings m WHERE m.incident_id=i.incident_id)");
        incidents.syncAll();

        audit(auditEvent, finding, reason, disposition, incidentIds);
        return disposition.equals("FALSE_POSITIVE")
                ? "Marked finding " + finding.findingId() + " as FALSE_POSITIVE and removed it from active coordinator findings.\n"
                : "Suppressed finding " + finding.findingId() + " and removed it from active coordinator findings.\n";
    }

    private void audit(String eventType, FindingRef finding, String reason,
                       String disposition, List<String> incidentIds) {
        try {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("finding_id", finding.findingId());
            details.put("finding_key", finding.findingKey());
            details.put("disposition", disposition);
            details.put("reason", reason);
            if (finding.ruleId() != null) details.put("rule_id", finding.ruleId());
            if (finding.subjectType() != null) details.put("subject_type", finding.subjectType());
            if (finding.subjectId() != null) details.put("subject_id", finding.subjectId());
            if (finding.targetHost() != null) details.put("target_host", finding.targetHost());
            if (finding.targetPort() != null) details.put("target_port", finding.targetPort());
            if (finding.severity() != null) details.put("severity", finding.severity());
            if (!incidentIds.isEmpty()) details.put("former_incidents", incidentIds);
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES (?,?,CAST(? AS jsonb))",
                    eventType, finding.agentId(), mapper.writeValueAsString(details));
        } catch (Exception e) {
            throw new IllegalStateException("failed to record finding disposition audit event", e);
        }
    }

    private void requireAdmin(String suppliedToken) {
        if (adminToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "finding administration is disabled; configure NETA_OPERATOR_ADMIN_TOKEN");
        }
        byte[] expected = adminToken.getBytes(StandardCharsets.UTF_8);
        byte[] supplied = (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, supplied)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
        }
    }

    private static void requireText(String value, String message) {
        if (value == null || value.isBlank()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private record FindingRef(String findingId, String findingKey, String agentId,
                              String ruleId, String subjectType, String subjectId,
                              String targetHost, Integer targetPort, String severity) {}
}
