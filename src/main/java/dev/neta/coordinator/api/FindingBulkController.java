package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.incident.IncidentService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
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
    private static final long MAX_AGE_SECONDS = 10L * 365 * 24 * 60 * 60;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final IncidentService incidents;
    private final String adminToken;

    public FindingBulkController(JdbcTemplate jdbc,
                                 ObjectMapper mapper,
                                 IncidentService incidents,
                                 @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.incidents = incidents;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @GetMapping("/finding-bulk-preview")
    public BulkPreview preview(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                               @RequestParam(required = false) String agent,
                               @RequestParam(required = false) String severity,
                               @RequestParam(required = false) String rule,
                               @RequestParam(required = false) String status,
                               @RequestParam(required = false) Long olderThanSeconds) {
        requireAdmin(suppliedToken);
        Filter filter = filter(agent, severity, rule, status, olderThanSeconds);
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
                              @RequestParam(required = false) Long olderThanSeconds,
                              @RequestParam String reason) {
        requireAdmin(suppliedToken);
        requireReason(reason);
        Filter filter = filter(agent, severity, rule, status, olderThanSeconds);
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
                            @RequestParam(required = false) String agent,
                            @RequestParam(required = false) String severity,
                            @RequestParam(required = false) String rule,
                            @RequestParam(required = false) String status,
                            @RequestParam(required = false) Long olderThanSeconds,
                            @RequestParam String reason) {
        requireAdmin(suppliedToken);
        requireReason(reason);
        Filter filter = filter(agent, severity, rule, status, olderThanSeconds);
        requireSelectiveFilter(filter);
        long count = count(filter);
        if (count == 0) return new BulkResult("PURGE", 0, "No findings matched the filter.");

        clearFindingReferences(filter);
        int changed = jdbc.update("DELETE FROM findings f " + filter.where(), filter.args().toArray());
        removeEmptyIncidents();
        incidents.syncAll();
        audit("FINDINGS_BULK_PURGED", filter, reason, changed);
        return new BulkResult("PURGE", changed, "Permanently purged " + changed + " finding(s).");
    }

    private long count(Filter filter) {
        Long value = jdbc.queryForObject("SELECT count(*) FROM findings f JOIN agents a ON a.agent_id=f.agent_id " + filter.where(),
                Long.class, filter.args().toArray());
        return value == null ? 0 : value;
    }

    private Map<String, Long> grouped(Filter filter, String expression) {
        Map<String, Long> result = new LinkedHashMap<>();
        jdbc.query("SELECT " + expression + " bucket,count(*) total FROM findings f JOIN agents a ON a.agent_id=f.agent_id "
                        + filter.where() + " GROUP BY bucket ORDER BY total DESC,bucket LIMIT 20",
                rs -> result.put(rs.getString("bucket"), rs.getLong("total")), filter.args().toArray());
        return result;
    }

    private void clearFindingReferences(Filter filter) {
        String selected = "SELECT f.finding_id FROM findings f JOIN agents a ON a.agent_id=f.agent_id " + filter.where();
        jdbc.update("UPDATE corroboration_requests SET finding_id=NULL WHERE finding_id IN (" + selected + ")",
                filter.args().toArray());
        jdbc.update("DELETE FROM incident_findings WHERE finding_id IN (" + selected + ")",
                filter.args().toArray());
    }

    private void removeEmptyIncidents() {
        jdbc.update("DELETE FROM incidents i WHERE NOT EXISTS (SELECT 1 FROM incident_findings m WHERE m.incident_id=i.incident_id)");
    }

    private void audit(String eventType, Filter filter, String reason, int affected) {
        try {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("affected", affected);
            details.put("reason", reason);
            if (text(filter.agent())) details.put("agent", filter.agent());
            if (text(filter.severity())) details.put("severity", filter.severity());
            if (text(filter.rule())) details.put("rule", filter.rule());
            if (text(filter.status())) details.put("status", filter.status());
            if (filter.olderThanSeconds() != null) details.put("older_than_seconds", filter.olderThanSeconds());
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES (?,NULL,CAST(? AS jsonb))",
                    eventType, mapper.writeValueAsString(details));
        } catch (Exception e) {
            throw new IllegalStateException("failed to record bulk finding audit event", e);
        }
    }

    private Filter filter(String agent, String severity, String rule, String status, Long olderThanSeconds) {
        if (olderThanSeconds != null && (olderThanSeconds <= 0 || olderThanSeconds > MAX_AGE_SECONDS)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "olderThanSeconds must be between 1 and " + MAX_AGE_SECONDS);
        }
        List<Object> args = new ArrayList<>();
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (text(agent)) {
            where.append(" AND (f.agent_id=? OR lower(COALESCE((SELECT ax.display_name FROM agents ax WHERE ax.agent_id=f.agent_id),''))=lower(?))");
            args.add(agent.trim());
            args.add(agent.trim());
        }
        if (text(severity)) {
            where.append(" AND upper(COALESCE(f.severity,''))=upper(?)");
            args.add(severity.trim());
        }
        if (text(rule)) {
            where.append(" AND upper(COALESCE(f.rule_id,''))=upper(?)");
            args.add(rule.trim());
        }
        if (text(status)) {
            where.append(" AND upper(COALESCE(f.status,''))=upper(?)");
            args.add(status.trim());
        }
        if (olderThanSeconds != null) {
            where.append(" AND f.last_seen < now() - (? * interval '1 second')");
            args.add(olderThanSeconds);
        }
        return new Filter(normalize(agent), normalize(severity), normalize(rule), normalize(status), olderThanSeconds,
                where.toString(), List.copyOf(args));
    }

    private static void requireSelectiveFilter(Filter filter) {
        if (!text(filter.agent()) && !text(filter.severity()) && !text(filter.rule())
                && !text(filter.status()) && filter.olderThanSeconds() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "bulk finding changes require at least one filter");
        }
    }

    private static void requireReason(String reason) {
        if (!text(reason)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason is required");
        if (reason.trim().length() > 1000) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason must be at most 1000 characters");
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

    private static String normalize(String value) {
        return text(value) ? value.trim() : null;
    }

    private static boolean text(String value) {
        return value != null && !value.isBlank();
    }

    public record BulkPreview(long count,
                              Map<String, Long> bySeverity,
                              Map<String, Long> byRule,
                              Map<String, Long> byAgent) {}

    public record BulkResult(String action, int affected, String message) {}

    private record Filter(String agent,
                          String severity,
                          String rule,
                          String status,
                          Long olderThanSeconds,
                          String where,
                          List<Object> args) {}
}
