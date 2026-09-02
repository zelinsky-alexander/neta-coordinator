package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/operator")
public class OperatorViewController {
    private static final Duration ONLINE_WINDOW = Duration.ofMinutes(2);
    private static final int DEFAULT_FINDING_LIMIT = 10;
    private static final int MAX_FINDING_LIMIT = 100;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public OperatorViewController(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @GetMapping(value = "/endpoints", produces = MediaType.TEXT_PLAIN_VALUE)
    public String endpoints() {
        Instant now = Instant.now();
        List<EndpointRow> rows = jdbc.query("""
                SELECT agent_id, display_name, status, last_seen_at, last_heartbeat_payload::text
                FROM agents
                ORDER BY COALESCE(NULLIF(display_name, ''), agent_id)
                """, (rs, rowNum) -> new EndpointRow(
                rs.getString("agent_id"), rs.getString("display_name"), rs.getString("status"),
                timestampToInstant(rs.getTimestamp("last_seen_at")), rs.getString("last_heartbeat_payload")));

        StringBuilder out = new StringBuilder();
        out.append(String.format("%-24s %-18s %-18s %-10s %s%n", "AGENT", "PLATFORM", "SITE", "STATUS", "LAST SEEN"));
        out.append("------------------------------------------------------------------------------------------\n");
        for (EndpointRow row : rows) {
            JsonNode heartbeat = parseJson(row.heartbeatPayload());
            String site = firstText(heartbeat, "site", "region", "location");
            if ("-".equals(site)) site = nestedText(heartbeat, "network", "site");
            out.append(String.format("%-24s %-18s %-18s %-10s %s%n",
                    trim(agentName(row), 24), trim(platform(heartbeat), 18), trim(site, 18),
                    endpointStatus(row, now), relativeAge(row.lastSeenAt(), now)));
        }
        return out.toString();
    }

    @GetMapping(value = "/findings", produces = MediaType.TEXT_PLAIN_VALUE)
    public String findings(@RequestParam(defaultValue = "10") int limit) {
        int boundedLimit = Math.max(1, Math.min(limit, MAX_FINDING_LIMIT));
        Instant now = Instant.now();
        Summary summary = jdbc.queryForObject("""
                SELECT count(*),
                       count(*) FILTER (WHERE status='ACTIVE'),
                       count(*) FILTER (WHERE upper(COALESCE(trust_verdict,''))='SUSPICIOUS')
                FROM findings
                """, (rs, n) -> new Summary(rs.getLong(1), rs.getLong(2), rs.getLong(3)));
        List<FindingRow> rows = jdbc.query("""
                SELECT f.finding_id, f.agent_id, a.display_name, f.target_host, f.target_port,
                       f.trust_verdict, f.performance_verdict, f.occurrence_count, f.status, f.last_seen
                FROM findings f
                JOIN agents a ON a.agent_id=f.agent_id
                ORDER BY f.last_seen DESC
                LIMIT ?
                """, (rs, n) -> new FindingRow(
                rs.getString("finding_id"), rs.getString("agent_id"), rs.getString("display_name"),
                rs.getString("target_host"), rs.getInt("target_port"), rs.getString("trust_verdict"),
                rs.getString("performance_verdict"), rs.getLong("occurrence_count"), rs.getString("status"),
                timestampToInstant(rs.getTimestamp("last_seen"))), boundedLimit);

        StringBuilder out = new StringBuilder();
        if (summary == null) summary = new Summary(0, 0, 0);
        out.append(String.format("Findings: total=%d active=%d suspicious=%d%n%n",
                summary.total(), summary.active(), summary.suspicious()));
        out.append(String.format("%-10s %-22s %-30s %-14s %-14s %5s %-9s %s%n",
                "LAST SEEN", "AGENT", "TARGET", "TRUST", "PERFORMANCE", "COUNT", "STATUS", "FINDING"));
        out.append("------------------------------------------------------------------------------------------------------------------------\n");
        for (FindingRow row : rows) {
            out.append(String.format("%-10s %-22s %-30s %-14s %-14s %5d %-9s %s%n",
                    relativeAge(row.lastSeen(), now), trim(displayOrId(row.displayName(), row.agentId()), 22),
                    trim(row.targetHost() + ":" + row.targetPort(), 30), value(row.trustVerdict()),
                    value(row.performanceVerdict()), row.occurrenceCount(), value(row.status()), row.findingId()));
        }
        return out.toString();
    }

    private JsonNode parseJson(String json) {
        if (json == null || json.isBlank()) return mapper.createObjectNode();
        try { return mapper.readTree(json); } catch (Exception ignored) { return mapper.createObjectNode(); }
    }

    private static String platform(JsonNode heartbeat) {
        String direct = firstText(heartbeat, "platform", "os");
        String arch = firstText(heartbeat, "arch", "architecture");
        if (!"-".equals(direct) && !"-".equals(arch) && !direct.contains("/")) return direct + "/" + arch;
        return direct;
    }

    private static String firstText(JsonNode node, String... fields) {
        for (String field : fields) {
            JsonNode value = node.path(field);
            if (value.isTextual() && !value.asText().isBlank()) return value.asText();
        }
        return "-";
    }

    private static String nestedText(JsonNode node, String parent, String field) {
        JsonNode value = node.path(parent).path(field);
        return value.isTextual() && !value.asText().isBlank() ? value.asText() : "-";
    }

    private static String endpointStatus(EndpointRow row, Instant now) {
        if (!"ACTIVE".equalsIgnoreCase(row.enrollmentStatus())) return "REVOKED";
        if (row.lastSeenAt() != null && Duration.between(row.lastSeenAt(), now).compareTo(ONLINE_WINDOW) <= 0) return "ONLINE";
        return "OFFLINE";
    }

    private static String agentName(EndpointRow row) { return displayOrId(row.displayName(), row.agentId()); }
    private static String displayOrId(String displayName, String id) { return displayName == null || displayName.isBlank() ? id : displayName; }
    private static String value(String s) { return s == null || s.isBlank() ? "-" : s.toUpperCase(Locale.ROOT); }
    private static String trim(String s, int width) { return s == null ? "-" : s.length() <= width ? s : s.substring(0, width - 1) + "…"; }

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

    private static Instant timestampToInstant(Timestamp ts) { return ts == null ? null : ts.toInstant(); }

    private record EndpointRow(String agentId, String displayName, String enrollmentStatus, Instant lastSeenAt, String heartbeatPayload) {}
    private record FindingRow(String findingId, String agentId, String displayName, String targetHost, int targetPort,
                              String trustVerdict, String performanceVerdict, long occurrenceCount, String status, Instant lastSeen) {}
    private record Summary(long total, long active, long suspicious) {}
}
