package dev.neta.coordinator.api;

import dev.neta.coordinator.config.CoordinatorProperties;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/operator")
public class EndpointHistoryController {
    private static final int MAX_HISTORY_LIMIT = 500;
    private final JdbcTemplate jdbc;
    private final CoordinatorProperties.Liveness liveness;

    public EndpointHistoryController(JdbcTemplate jdbc, CoordinatorProperties properties) {
        this.jdbc = jdbc;
        this.liveness = properties.liveness();
    }

    @GetMapping(value = "/endpoints-filtered", produces = MediaType.TEXT_PLAIN_VALUE)
    public String endpointsFiltered(@RequestParam("status") String status) {
        String wanted = status.trim().toUpperCase(Locale.ROOT);
        if (!List.of("ONLINE", "STALE", "OFFLINE", "REVOKED", "NEVER_SEEN").contains(wanted)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "status must be online, stale, offline, revoked, or never_seen");
        }
        Instant now = Instant.now();
        List<EndpointRow> rows = jdbc.query("""
                SELECT agent_id, display_name, status, last_seen_at
                FROM agents
                ORDER BY COALESCE(NULLIF(display_name,''), agent_id)
                """, (rs, n) -> new EndpointRow(rs.getString(1), rs.getString(2), rs.getString(3), toInstant(rs.getTimestamp(4))));

        StringBuilder out = new StringBuilder();
        out.append(String.format("%-24s %-12s %s%n", "AGENT", "STATUS", "LAST SEEN"));
        out.append("------------------------------------------------------------\n");
        for (EndpointRow row : rows) {
            String state = state(row, now);
            if (!wanted.equals(state)) continue;
            out.append(String.format("%-24s %-12s %s%n", trim(name(row), 24), state, relativeAge(row.lastSeen(), now)));
        }
        return out.toString();
    }

    @GetMapping(value = "/endpoint-history", produces = MediaType.TEXT_PLAIN_VALUE)
    public String endpointHistory(@RequestParam("agent") String agent,
                                  @RequestParam(defaultValue = "24h") String last,
                                  @RequestParam(required = false) String type,
                                  @RequestParam(defaultValue = "100") int limit) {
        String agentId = resolveAgentId(agent);
        Duration window = parseWindow(last);
        int boundedLimit = Math.max(1, Math.min(limit, MAX_HISTORY_LIMIT));
        Instant cutoff = Instant.now().minus(window);

        String sql = """
                SELECT contact_at, message_type, sequence, message_id
                FROM endpoint_contact_history
                WHERE agent_id=? AND contact_at>=?
                """ + ((type == null || type.isBlank()) ? "" : " AND lower(message_type)=lower(?) ") +
                " ORDER BY contact_at DESC LIMIT ?";

        List<ContactRow> rows;
        if (type == null || type.isBlank()) {
            rows = jdbc.query(sql, (rs, n) -> new ContactRow(toInstant(rs.getTimestamp(1)), rs.getString(2), rs.getLong(3), rs.getString(4)),
                    agentId, Timestamp.from(cutoff), boundedLimit);
        } else {
            rows = jdbc.query(sql, (rs, n) -> new ContactRow(toInstant(rs.getTimestamp(1)), rs.getString(2), rs.getLong(3), rs.getString(4)),
                    agentId, Timestamp.from(cutoff), type, boundedLimit);
        }

        StringBuilder out = new StringBuilder();
        out.append("Endpoint history: ").append(agent).append("  last=").append(last);
        if (type != null && !type.isBlank()) out.append("  type=").append(type);
        out.append("\n\n");
        out.append(String.format("%-25s %-24s %10s %s%n", "TIME", "TYPE", "SEQUENCE", "MESSAGE"));
        out.append("------------------------------------------------------------------------------------------\n");
        for (ContactRow row : rows) {
            out.append(String.format("%-25s %-24s %10d %s%n", row.at(), row.type(), row.sequence(), row.messageId()));
        }
        if (rows.isEmpty()) out.append("<no retained contacts in this window>\n");
        return out.toString();
    }

    @GetMapping(value = "/endpoint-context", produces = MediaType.TEXT_PLAIN_VALUE)
    public String endpointContext(@RequestParam("agent") String agent) {
        String agentId = resolveAgentId(agent);
        List<RecentFinding> findings = jdbc.query("""
                SELECT finding_id,target_host,target_port,trust_verdict,last_seen
                FROM findings WHERE agent_id=? ORDER BY last_seen DESC LIMIT 5
                """, (rs, n) -> new RecentFinding(rs.getString(1), rs.getString(2), rs.getInt(3), rs.getString(4), toInstant(rs.getTimestamp(5))), agentId);
        List<RecentIncident> incidents = jdbc.query("""
                SELECT incident_id,target_host,target_port,status,last_seen,finding_count
                FROM incidents WHERE agent_id=? ORDER BY last_seen DESC LIMIT 5
                """, (rs, n) -> new RecentIncident(rs.getString(1), rs.getString(2), rs.getInt(3), rs.getString(4), toInstant(rs.getTimestamp(5)), rs.getInt(6)), agentId);

        StringBuilder out = new StringBuilder();
        out.append("\nRecent findings:\n");
        if (findings.isEmpty()) out.append("  <none>\n");
        for (RecentFinding f : findings) {
            out.append(String.format("  %-32s %-24s %-12s %s%n", trim(f.id(),32), trim(f.host()+":"+f.port(),24), value(f.trust()), f.lastSeen()));
        }
        out.append("\nRecent incidents:\n");
        if (incidents.isEmpty()) out.append("  <none>\n");
        for (RecentIncident i : incidents) {
            out.append(String.format("  %-26s %-24s %-8s findings=%d  %s%n", trim(i.id(),26), trim(i.host()+":"+i.port(),24), value(i.status()), i.count(), i.lastSeen()));
        }
        return out.toString();
    }

    private String resolveAgentId(String agent) {
        List<String> ids = jdbc.query("""
                SELECT agent_id FROM agents
                WHERE agent_id=? OR display_name=?
                ORDER BY CASE WHEN agent_id=? THEN 0 ELSE 1 END
                LIMIT 1
                """, (rs, n) -> rs.getString(1), agent, agent, agent);
        if (ids.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "endpoint not found");
        return ids.getFirst();
    }

    private Duration parseWindow(String value) {
        String v = value.trim().toLowerCase(Locale.ROOT);
        try {
            if (v.matches("[1-9][0-9]*m")) return Duration.ofMinutes(Long.parseLong(v.substring(0, v.length()-1)));
            if (v.matches("[1-9][0-9]*h")) return Duration.ofHours(Long.parseLong(v.substring(0, v.length()-1)));
            if (v.matches("[1-9][0-9]*d")) return Duration.ofDays(Long.parseLong(v.substring(0, v.length()-1)));
            if (v.startsWith("pt") || v.startsWith("p")) return Duration.parse(value.toUpperCase(Locale.ROOT));
        } catch (RuntimeException ignored) { }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "last must look like 30m, 24h, 7d, or an ISO-8601 duration");
    }

    private String state(EndpointRow row, Instant now) {
        if (!"ACTIVE".equalsIgnoreCase(row.enrollmentStatus())) return "REVOKED";
        if (row.lastSeen() == null) return "NEVER_SEEN";
        Duration age = Duration.between(row.lastSeen(), now);
        if (age.isNegative() || age.compareTo(liveness.onlineThreshold()) <= 0) return "ONLINE";
        if (age.compareTo(liveness.offlineThreshold()) <= 0) return "STALE";
        return "OFFLINE";
    }

    private static String name(EndpointRow row) { return row.displayName() == null || row.displayName().isBlank() ? row.agentId() : row.displayName(); }
    private static String value(String s) { return s == null || s.isBlank() ? "-" : s.toUpperCase(Locale.ROOT); }
    private static String trim(String s, int width) { return s == null ? "-" : s.length() <= width ? s : s.substring(0, width - 1) + "…"; }
    private static Instant toInstant(Timestamp ts) { return ts == null ? null : ts.toInstant(); }
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

    private record EndpointRow(String agentId, String displayName, String enrollmentStatus, Instant lastSeen) {}
    private record ContactRow(Instant at, String type, long sequence, String messageId) {}
    private record RecentFinding(String id, String host, int port, String trust, Instant lastSeen) {}
    private record RecentIncident(String id, String host, int port, String status, Instant lastSeen, int count) {}
}
