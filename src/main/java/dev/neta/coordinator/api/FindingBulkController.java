package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.incident.IncidentService;
import dev.neta.coordinator.finding.FindingQueryService;
import dev.neta.coordinator.security.PortalAuthorization;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/operator")
public class FindingBulkController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final IncidentService incidents;
    private final PortalAuthorization portalAuthorization;
    private final FindingQueryService findingQueries;
    private final String adminToken;

    public FindingBulkController(JdbcTemplate jdbc,
                                 ObjectMapper mapper,
                                 IncidentService incidents,
                                 PortalAuthorization portalAuthorization,
                                 FindingQueryService findingQueries,
                                 @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.incidents = incidents;
        this.portalAuthorization = portalAuthorization;
        this.findingQueries = findingQueries;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @GetMapping("/finding-bulk-preview")
    public BulkPreview preview(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                               @RequestParam(required = false) String agent,
                               @RequestParam(required = false) String severity,
                               @RequestParam(required = false) String rule,
                               @RequestParam(required = false) String status,
                               @RequestParam(required = false) String assessment,
                               @RequestParam(required = false) Long olderThanSeconds,
                               @RequestParam(required = false) Long newerThanSeconds) {
        requireAdmin(suppliedToken);
        Filter filter = filter(agent, severity, rule, status, assessment, olderThanSeconds, newerThanSeconds);
        long count = count(filter);
        return new BulkPreview(count,
                grouped(filter, "COALESCE(NULLIF(upper(f.severity),''),'-')"),
                grouped(filter, "COALESCE(NULLIF(f.rule_id,''),'-')"),
                grouped(filter, "COALESCE(NULLIF(a.display_name,''),f.agent_id)"));
    }

    @PostMapping("/finding-bulk-resolve")
    @Transactional
    public BulkResult resolve(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                              @RequestParam(required = false) String agent,
                              @RequestParam(required = false) String severity,
                              @RequestParam(required = false) String rule,
                              @RequestParam(required = false) String status,
                              @RequestParam(required = false) String assessment,
                              @RequestParam(required = false) Long olderThanSeconds,
                              @RequestParam(required = false) Long newerThanSeconds,
                              @RequestParam String reason) {
        requireAdmin(suppliedToken);
        requireReason(reason);
        Filter filter = filter(agent, severity, rule, status, assessment, olderThanSeconds, newerThanSeconds);
        requireSelectiveFilter(filter);
        long count = count(filter);
        if (count == 0) return new BulkResult("RESOLVE", 0, "No findings matched the filter.");
        clearFindingReferences(filter);
        int changed = jdbc.update("UPDATE findings f SET status='RESOLVED' " + filter.where(), filter.args().toArray());
        removeEmptyIncidents();
        incidents.syncAll();
        audit("FINDINGS_BULK_RESOLVED", filter, reason, changed);
        return new BulkResult("RESOLVE", changed,
                "Resolved " + changed + " finding(s). History was retained; a recurring finding may become ACTIVE again.");
    }

    @PostMapping("/finding-bulk-purge")
    @Transactional
    public BulkResult purge(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                            @RequestHeader(value = "X-NETA-Portal-Service-Token", required = false) String portalToken,
                            @RequestHeader(value = "X-NETA-Actor", required = false) String portalActor,
                            @RequestHeader(value = "X-NETA-Actor-Role", required = false) String portalRole,
                            @RequestHeader(value = "X-NETA-Portal-Service", required = false) String portalService,
                            @RequestHeader(value = "X-Request-ID", required = false) String requestId,
                            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
                            @RequestParam(required = false) String agent,
                            @RequestParam(required = false) String severity,
                            @RequestParam(required = false) String rule,
                            @RequestParam(required = false) String status,
                            @RequestParam(required = false) String assessment,
                            @RequestParam(required = false) Long olderThanSeconds,
                            @RequestParam(required = false) Long newerThanSeconds,
                            @RequestParam String reason,
                            @RequestParam(defaultValue = "false") boolean confirmed) {
        requireAdmin(suppliedToken);
        String actor = authorizePurge(portalToken, portalActor, portalRole, portalService,
                requestId, idempotencyKey);
        requireConfirmation(confirmed);
        requireReason(reason);
        Filter filter = filter(agent, severity, rule, status, assessment, olderThanSeconds, newerThanSeconds);
        requireSelectiveFilter(filter);
        BulkResult replay = priorPurge(idempotencyKey);
        if (replay != null) return replay;
        long count = count(filter);
        if (count == 0) {
            audit("FINDINGS_BULK_PURGED", filter, reason, 0, actor, requestId, idempotencyKey);
            return new BulkResult("PURGE", 0, "No findings matched the filter.");
        }
        clearFindingReferences(filter);
        int changed = jdbc.update("DELETE FROM findings f " + filter.where(), filter.args().toArray());
        removeEmptyIncidents();
        incidents.syncAll();
        audit("FINDINGS_BULK_PURGED", filter, reason, changed, actor, requestId, idempotencyKey);
        return new BulkResult("PURGE", changed, "Permanently purged " + changed + " finding(s).");
    }

    @PostMapping("/finding-purge")
    @Transactional
    public BulkResult purgeOne(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                               @RequestHeader(value = "X-NETA-Portal-Service-Token", required = false) String portalToken,
                               @RequestHeader(value = "X-NETA-Actor", required = false) String portalActor,
                               @RequestHeader(value = "X-NETA-Actor-Role", required = false) String portalRole,
                               @RequestHeader(value = "X-NETA-Portal-Service", required = false) String portalService,
                               @RequestHeader(value = "X-Request-ID", required = false) String requestId,
                               @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
                               @RequestParam("id") String findingId,
                               @RequestParam String reason,
                               @RequestParam(defaultValue = "false") boolean confirmed) {
        requireAdmin(suppliedToken);
        String actor = authorizePurge(portalToken, portalActor, portalRole, portalService,
                requestId, idempotencyKey);
        requireConfirmation(confirmed);
        requireReason(reason);
        if (!text(findingId)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "finding id is required");
        BulkResult replay = priorPurge(idempotencyKey);
        if (replay != null) return replay;
        jdbc.update("UPDATE corroboration_requests SET finding_id=NULL WHERE finding_id=?", findingId.trim());
        jdbc.update("DELETE FROM incident_findings WHERE finding_id=?", findingId.trim());
        int changed = jdbc.update("DELETE FROM findings WHERE finding_id=?", findingId.trim());
        removeEmptyIncidents();
        incidents.syncAll();
        Filter selection = new Filter(null, null, null, null, null, null, null,
                " WHERE f.finding_id=?", List.of(findingId.trim()));
        audit("FINDING_PURGED", selection, reason, changed, actor, requestId, idempotencyKey);
        return new BulkResult("PURGE", changed, changed == 0
                ? "Finding was already absent." : "Permanently purged finding " + findingId.trim() + ".");
    }

    private long count(Filter filter) {
        Long value = jdbc.queryForObject("SELECT count(*) FROM findings f JOIN agents a ON a.agent_id=f.agent_id " + filter.where(),
                Long.class, filter.args().toArray());
        return value == null ? 0 : value;
    }

    private Map<String, Long> grouped(Filter filter, String expression) {
        Map<String, Long> result = new LinkedHashMap<>();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT " + expression + " bucket,count(*) total FROM findings f JOIN agents a ON a.agent_id=f.agent_id "
                        + filter.where() + " GROUP BY bucket ORDER BY total DESC,bucket LIMIT 20",
                filter.args().toArray());
        for (Map<String, Object> row : rows) {
            Object bucket = row.get("bucket");
            Object total = row.get("total");
            if (bucket != null && total instanceof Number number) result.put(bucket.toString(), number.longValue());
        }
        return result;
    }

    private void clearFindingReferences(Filter filter) {
        String selected = "SELECT f.finding_id FROM findings f JOIN agents a ON a.agent_id=f.agent_id " + filter.where();
        jdbc.update("UPDATE corroboration_requests SET finding_id=NULL WHERE finding_id IN (" + selected + ")", filter.args().toArray());
        jdbc.update("DELETE FROM incident_findings WHERE finding_id IN (" + selected + ")", filter.args().toArray());
    }

    private void removeEmptyIncidents() {
        jdbc.update("DELETE FROM incidents i WHERE NOT EXISTS (SELECT 1 FROM incident_findings m WHERE m.incident_id=i.incident_id)");
    }

    private void audit(String eventType, Filter filter, String reason, int affected) {
        audit(eventType, filter, reason, affected, "operator-cli", null, null);
    }

    private void audit(String eventType, Filter filter, String reason, int affected, String actor,
                       String requestId, String idempotencyKey) {
        try {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("affected", affected);
            details.put("reason", reason);
            details.put("actor", actor);
            details.put("request_id", requestId);
            details.put("idempotency_key", idempotencyKey);
            details.put("selection_sql", filter.where());
            details.put("selection_args", filter.args());
            if (text(filter.agent())) details.put("agent", filter.agent());
            if (text(filter.severity())) details.put("severity", filter.severity());
            if (text(filter.rule())) details.put("rule", filter.rule());
            if (text(filter.status())) details.put("status", filter.status());
            if (text(filter.assessment())) details.put("assessment", filter.assessment());
            if (filter.olderThanSeconds() != null) details.put("older_than_seconds", filter.olderThanSeconds());
            if (filter.newerThanSeconds() != null) details.put("newer_than_seconds", filter.newerThanSeconds());
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES (?,NULL,CAST(? AS jsonb))",
                    eventType, mapper.writeValueAsString(details));
        } catch (Exception e) {
            throw new IllegalStateException("failed to record bulk finding audit event", e);
        }
    }

    private BulkResult priorPurge(String idempotencyKey) {
        if (!text(idempotencyKey)) return null;
        List<Integer> affected = jdbc.query("""
                SELECT COALESCE((details->>'affected')::integer,0)
                FROM audit_events
                WHERE event_type IN ('FINDING_PURGED','FINDINGS_BULK_PURGED')
                  AND details->>'idempotency_key'=?
                ORDER BY created_at DESC LIMIT 1
                """, (rs, ignored) -> rs.getInt(1), idempotencyKey);
        return affected.isEmpty() ? null : new BulkResult("PURGE", affected.getFirst(),
                "Purge request was already completed; returning the recorded result.");
    }

    private String authorizePurge(String portalToken, String actor, String role, String service,
                                  String requestId, String idempotencyKey) {
        if (!text(idempotencyKey)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Idempotency-Key is required for permanent purge");
        if (!text(portalToken)) return "operator-cli";
        return portalAuthorization.require(portalToken, actor, role, service, requestId,
                idempotencyKey, PortalAuthorization.Role.ADMIN).user();
    }

    private static void requireConfirmation(boolean confirmed) {
        if (!confirmed) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "permanent purge requires confirmed=true");
    }

    private Filter filter(String agent, String severity, String rule, String status, String assessment,
                          Long olderThanSeconds, Long newerThanSeconds) {
        FindingQueryService.Selection selection = findingQueries.selection(new FindingQueryService.Filter(
                agent, null, null, status, null, severity, rule, assessment,
                olderThanSeconds, newerThanSeconds));
        return new Filter(normalize(agent), normalize(severity), normalize(rule), normalize(status), normalize(assessment),
                olderThanSeconds, newerThanSeconds, selection.where(), selection.args());
    }

    private static void requireSelectiveFilter(Filter filter) {
        if (!text(filter.agent()) && !text(filter.severity()) && !text(filter.rule()) && !text(filter.status())
                && !text(filter.assessment()) && filter.olderThanSeconds() == null && filter.newerThanSeconds() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"bulk finding changes require at least one filter");
        }
    }

    private static void requireReason(String reason) {
        if (!text(reason)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason is required");
        if (reason.trim().length() > 1000) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason must be at most 1000 characters");
    }

    private void requireAdmin(String suppliedToken) {
        if (adminToken.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "finding administration is disabled; configure NETA_OPERATOR_ADMIN_TOKEN");
        byte[] expected = adminToken.getBytes(StandardCharsets.UTF_8);
        byte[] supplied = (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, supplied)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
    }

    private static String normalize(String value) { return text(value) ? value.trim() : null; }
    private static boolean text(String value) { return value != null && !value.isBlank(); }

    public record BulkPreview(long count, Map<String, Long> bySeverity, Map<String, Long> byRule, Map<String, Long> byAgent) {}
    public record BulkResult(String action, int affected, String message) {}
    private record Filter(String agent, String severity, String rule, String status, String assessment,
                          Long olderThanSeconds, Long newerThanSeconds, String where, List<Object> args) {}
}
