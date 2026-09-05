package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
public class AgentAdminController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final String adminToken;

    public AgentAdminController(JdbcTemplate jdbc,
                                ObjectMapper mapper,
                                @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @GetMapping(value = "/agents", produces = MediaType.TEXT_PLAIN_VALUE)
    public String agents() {
        Instant now = Instant.now();
        List<AgentRow> rows = jdbc.query(agentSelect() + " ORDER BY COALESCE(NULLIF(display_name,''), agent_id)",
                (rs, n) -> mapAgent(rs));

        StringBuilder out = new StringBuilder();
        out.append(String.format("%-24s %-10s %-12s %-16s %-18s %-12s %s%n",
                "AGENT", "STATE", "VERSION", "BUILD", "PLATFORM", "LAST SEEN", "AGENT ID"));
        out.append("----------------------------------------------------------------------------------------------------------------------\n");
        for (AgentRow row : rows) {
            out.append(String.format("%-24s %-10s %-12s %-16s %-18s %-12s %s%n",
                    trim(displayOrId(row.displayName(), row.agentId()), 24), row.status(),
                    trim(value(row.agentVersion()), 12), trim(value(row.agentBuildId()), 16),
                    trim(platform(row), 18), relativeAge(row.lastSeenAt(), now), row.agentId()));
        }
        return out.toString();
    }

    @GetMapping(value = "/agent-admin", produces = MediaType.TEXT_PLAIN_VALUE)
    public String agent(@RequestParam("agent") String agent) {
        AgentRow row = resolveAgent(agent);
        StringBuilder out = new StringBuilder();
        line(out, "Agent", displayOrId(row.displayName(), row.agentId()));
        line(out, "Agent ID", row.agentId());
        line(out, "Enrollment state", row.status());
        line(out, "Enrolled", instant(row.enrolledAt()));
        line(out, "Last seen", instant(row.lastSeenAt()));
        line(out, "Last sequence", Long.toString(row.lastSequence()));
        line(out, "Version", row.agentVersion());
        line(out, "Build ID", row.agentBuildId());
        line(out, "Git commit", row.agentGitCommit());
        line(out, "Platform", platform(row));
        line(out, "Artifact SHA-256", row.agentArtifactSha256());
        line(out, "Protocol version", integer(row.agentProtocolVersion()));
        line(out, "Schema version", integer(row.agentSchemaVersion()));
        line(out, "Features", features(row.agentFeatures()));
        line(out, "Build reported", instant(row.buildReportedAt()));
        line(out, "Certificate SHA-256", row.certificateSha256());
        out.append("\nRecent administration\n");
        out.append("---------------------------------\n");
        List<AuditRow> audit = jdbc.query("""
                SELECT event_type, details::text, created_at
                FROM audit_events
                WHERE agent_id=? AND event_type IN ('AGENT_REVOKED','AGENT_REACTIVATED')
                ORDER BY created_at DESC
                LIMIT 10
                """, (rs, n) -> new AuditRow(rs.getString("event_type"), rs.getString("details"),
                toInstant(rs.getTimestamp("created_at"))), row.agentId());
        if (audit.isEmpty()) {
            out.append("No administration events.\n");
        } else {
            for (AuditRow event : audit) {
                out.append(event.createdAt()).append("  ").append(event.eventType()).append("  ")
                        .append(event.details()).append('\n');
            }
        }
        return out.toString();
    }

    @PostMapping(value = "/agent-revoke", produces = MediaType.TEXT_PLAIN_VALUE)
    @Transactional
    public String revoke(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                         @RequestParam("agent") String agent,
                         @RequestParam("reason") String reason) {
        requireAdmin(suppliedToken);
        requireReason(reason);
        AgentRow row = resolveAgent(agent);
        if ("REVOKED".equals(row.status())) {
            return "Agent " + displayOrId(row.displayName(), row.agentId()) + " is already REVOKED.\n";
        }
        jdbc.update("UPDATE agents SET status='REVOKED' WHERE agent_id=?", row.agentId());
        audit("AGENT_REVOKED", row, "ACTIVE", "REVOKED", reason);
        return "Revoked agent " + displayOrId(row.displayName(), row.agentId()) + " (" + row.agentId() + ").\n"
                + "Future agent messages are rejected until reactivated.\n";
    }

    @PostMapping(value = "/agent-reactivate", produces = MediaType.TEXT_PLAIN_VALUE)
    @Transactional
    public String reactivate(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                             @RequestParam("agent") String agent,
                             @RequestParam("reason") String reason) {
        requireAdmin(suppliedToken);
        requireReason(reason);
        AgentRow row = resolveAgent(agent);
        if ("ACTIVE".equals(row.status())) {
            return "Agent " + displayOrId(row.displayName(), row.agentId()) + " is already ACTIVE.\n";
        }
        jdbc.update("UPDATE agents SET status='ACTIVE' WHERE agent_id=?", row.agentId());
        audit("AGENT_REACTIVATED", row, "REVOKED", "ACTIVE", reason);
        return "Reactivated agent " + displayOrId(row.displayName(), row.agentId()) + " (" + row.agentId() + ").\n"
                + "The existing enrolled certificate identity is trusted again.\n";
    }

    private AgentRow resolveAgent(String agent) {
        List<AgentRow> rows = jdbc.query(agentSelect() + """
                WHERE agent_id=? OR display_name=?
                ORDER BY CASE WHEN agent_id=? THEN 0 ELSE 1 END
                LIMIT 1
                """, (rs, n) -> mapAgent(rs), agent, agent, agent);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "agent not found");
        return rows.getFirst();
    }

    private static String agentSelect() {
        return """
                SELECT agent_id, display_name, status, enrolled_at, last_seen_at, last_sequence,
                       certificate_sha256, agent_version, agent_build_id, agent_git_commit,
                       agent_os, agent_arch, agent_artifact_sha256, agent_protocol_version,
                       agent_schema_version, agent_features::text AS agent_features, build_reported_at
                FROM agents
                """;
    }

    private static AgentRow mapAgent(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new AgentRow(
                rs.getString("agent_id"), rs.getString("display_name"), rs.getString("status"),
                toInstant(rs.getTimestamp("enrolled_at")), toInstant(rs.getTimestamp("last_seen_at")),
                rs.getLong("last_sequence"), rs.getString("certificate_sha256"),
                rs.getString("agent_version"), rs.getString("agent_build_id"), rs.getString("agent_git_commit"),
                rs.getString("agent_os"), rs.getString("agent_arch"), rs.getString("agent_artifact_sha256"),
                rs.getObject("agent_protocol_version", Integer.class), rs.getObject("agent_schema_version", Integer.class),
                rs.getString("agent_features"), toInstant(rs.getTimestamp("build_reported_at")));
    }

    private void requireAdmin(String suppliedToken) {
        if (adminToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "agent administration is disabled; configure NETA_OPERATOR_ADMIN_TOKEN");
        }
        byte[] expected = adminToken.getBytes(StandardCharsets.UTF_8);
        byte[] supplied = (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, supplied)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
        }
    }

    private static void requireReason(String reason) {
        if (reason == null || reason.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason is required");
        }
        if (reason.length() > 500) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason must be at most 500 characters");
        }
    }

    private void audit(String eventType, AgentRow row, String previous, String next, String reason) {
        try {
            String details = mapper.writeValueAsString(java.util.Map.of(
                    "previous_status", previous,
                    "new_status", next,
                    "reason", reason,
                    "display_name", displayOrId(row.displayName(), row.agentId())));
            jdbc.update("INSERT INTO audit_events(event_type, agent_id, details) VALUES (?, ?, CAST(? AS jsonb))",
                    eventType, row.agentId(), details);
        } catch (Exception e) {
            throw new IllegalStateException("failed to record administration audit event", e);
        }
    }

    private static Instant toInstant(Timestamp ts) { return ts == null ? null : ts.toInstant(); }
    private static String instant(Instant value) { return value == null ? "-" : value.toString(); }
    private static String displayOrId(String name, String id) { return name == null || name.isBlank() ? id : name; }
    private static String trim(String value, int width) { return value.length() <= width ? value : value.substring(0, width - 1) + "…"; }
    private static String value(String value) { return value == null || value.isBlank() ? "-" : value; }
    private static String integer(Integer value) { return value == null ? "-" : value.toString(); }
    private static String platform(AgentRow row) {
        String os = value(row.agentOs());
        String arch = value(row.agentArch());
        if ("-".equals(os)) return "-";
        return "-".equals(arch) ? os : os + "/" + arch;
    }
    private String features(String raw) {
        if (raw == null || raw.isBlank()) return "-";
        try {
            var node = mapper.readTree(raw);
            if (!node.isArray() || node.isEmpty()) return "-";
            StringBuilder out = new StringBuilder();
            for (var item : node) {
                if (!item.isTextual()) continue;
                if (!out.isEmpty()) out.append(", ");
                out.append(item.asText());
            }
            return out.isEmpty() ? "-" : out.toString();
        } catch (Exception ignored) {
            return "-";
        }
    }
    private static void line(StringBuilder out, String label, String value) { out.append(String.format("%-20s %s%n", label + ":", value(value))); }

    private static String relativeAge(Instant then, Instant now) {
        if (then == null) return "never";
        long seconds = Math.max(0, Duration.between(then, now).getSeconds());
        if (seconds < 60) return seconds + " sec";
        long minutes = seconds / 60;
        if (minutes < 60) return minutes + " min";
        long hours = minutes / 60;
        if (hours < 48) return hours + " hr";
        return (hours / 24) + " day";
    }

    private record AgentRow(String agentId, String displayName, String status, Instant enrolledAt,
                            Instant lastSeenAt, long lastSequence, String certificateSha256,
                            String agentVersion, String agentBuildId, String agentGitCommit,
                            String agentOs, String agentArch, String agentArtifactSha256,
                            Integer agentProtocolVersion, Integer agentSchemaVersion,
                            String agentFeatures, Instant buildReportedAt) {}
    private record AuditRow(String eventType, String details, Instant createdAt) {}
}
