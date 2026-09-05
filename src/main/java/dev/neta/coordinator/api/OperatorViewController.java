package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/operator")
public class OperatorViewController {
    private static final int MAX_FINDING_LIMIT = 100;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final CoordinatorProperties.Liveness liveness;

    public OperatorViewController(JdbcTemplate jdbc, ObjectMapper mapper, CoordinatorProperties properties) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.liveness = properties.liveness();
    }

    @GetMapping(value = "/endpoints", produces = MediaType.TEXT_PLAIN_VALUE)
    public String endpoints() {
        Instant now = Instant.now();
        List<EndpointRow> rows = jdbc.query("""
                SELECT agent_id, display_name, status, last_seen_at, last_heartbeat_payload::text,
                       agent_version, agent_build_id, agent_os, agent_arch
                FROM agents
                ORDER BY COALESCE(NULLIF(display_name, ''), agent_id)
                """, (rs, rowNum) -> new EndpointRow(
                rs.getString("agent_id"), rs.getString("display_name"), rs.getString("status"),
                timestampToInstant(rs.getTimestamp("last_seen_at")), rs.getString("last_heartbeat_payload"),
                rs.getString("agent_version"), rs.getString("agent_build_id"),
                rs.getString("agent_os"), rs.getString("agent_arch")));

        StringBuilder out = new StringBuilder();
        out.append(String.format("%-24s %-12s %-16s %-18s %-18s %-12s %s%n",
                "AGENT", "VERSION", "BUILD", "PLATFORM", "SITE", "STATUS", "LAST SEEN"));
        out.append("------------------------------------------------------------------------------------------------------------------------\n");
        for (EndpointRow row : rows) {
            JsonNode heartbeat = parseJson(row.heartbeatPayload());
            String site = firstText(heartbeat, "site", "region", "location");
            if ("-".equals(site)) site = nestedText(heartbeat, "network", "site");
            out.append(String.format("%-24s %-12s %-16s %-18s %-18s %-12s %s%n",
                    trim(agentName(row), 24), trim(valueRaw(row.agentVersion()), 12),
                    trim(valueRaw(row.agentBuildId()), 16), trim(platform(row, heartbeat), 18), trim(site, 18),
                    endpointStatus(row, now), relativeAge(row.lastSeenAt(), now)));
        }
        return out.toString();
    }

    @GetMapping(value = "/endpoints/{agentId}", produces = MediaType.TEXT_PLAIN_VALUE)
    public String endpoint(@PathVariable String agentId) {
        List<EndpointDetail> rows = jdbc.query("""
                SELECT agent_id, fleet_id, display_name, certificate_sha256, status, last_sequence,
                       enrolled_at, last_seen_at, last_heartbeat_payload::text,
                       agent_version, agent_build_id, agent_git_commit, agent_os, agent_arch,
                       agent_artifact_sha256, agent_protocol_version, agent_schema_version,
                       agent_features::text AS agent_features, build_reported_at
                FROM agents
                WHERE agent_id=? OR display_name=?
                ORDER BY CASE WHEN agent_id=? THEN 0 ELSE 1 END
                LIMIT 1
                """, (rs, n) -> new EndpointDetail(
                rs.getString("agent_id"), rs.getString("fleet_id"), rs.getString("display_name"),
                rs.getString("certificate_sha256"), rs.getString("status"), rs.getLong("last_sequence"),
                timestampToInstant(rs.getTimestamp("enrolled_at")), timestampToInstant(rs.getTimestamp("last_seen_at")),
                rs.getString("last_heartbeat_payload"), rs.getString("agent_version"), rs.getString("agent_build_id"),
                rs.getString("agent_git_commit"), rs.getString("agent_os"), rs.getString("agent_arch"),
                rs.getString("agent_artifact_sha256"), rs.getObject("agent_protocol_version", Integer.class),
                rs.getObject("agent_schema_version", Integer.class), rs.getString("agent_features"),
                timestampToInstant(rs.getTimestamp("build_reported_at"))), agentId, agentId, agentId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "endpoint not found");

        EndpointDetail row = rows.getFirst();
        Instant now = Instant.now();
        JsonNode heartbeat = parseJson(row.heartbeatPayload());
        String site = firstText(heartbeat, "site", "region", "location");
        if ("-".equals(site)) site = nestedText(heartbeat, "network", "site");
        EndpointRow statusRow = new EndpointRow(row.agentId(), row.displayName(), row.enrollmentStatus(), row.lastSeenAt(),
                row.heartbeatPayload(), row.agentVersion(), row.agentBuildId(), row.agentOs(), row.agentArch());

        StringBuilder out = new StringBuilder();
        line(out, "Agent", displayOrId(row.displayName(), row.agentId()));
        line(out, "Agent ID", row.agentId());
        line(out, "Fleet", row.fleetId());
        line(out, "Version", row.agentVersion());
        line(out, "Build ID", row.agentBuildId());
        line(out, "Git commit", row.agentGitCommit());
        line(out, "Platform", platform(statusRow, heartbeat));
        line(out, "Artifact SHA-256", row.agentArtifactSha256());
        line(out, "Protocol version", integer(row.agentProtocolVersion()));
        line(out, "Schema version", integer(row.agentSchemaVersion()));
        line(out, "Features", features(row.agentFeatures()));
        line(out, "Build reported", instant(row.buildReportedAt()));
        line(out, "Site", site);
        line(out, "Status", endpointStatus(statusRow, now));
        line(out, "Enrollment", value(row.enrollmentStatus()));
        line(out, "Last seen", row.lastSeenAt() == null ? "never" : relativeAge(row.lastSeenAt(), now) + " (" + row.lastSeenAt() + ")");
        line(out, "Online threshold", liveness.onlineThreshold().toString());
        line(out, "Offline threshold", liveness.offlineThreshold().toString());
        line(out, "Enrolled", row.enrolledAt() == null ? "-" : row.enrolledAt().toString());
        line(out, "Last sequence", Long.toString(row.lastSequence()));
        line(out, "Certificate SHA-256", valueRaw(row.certificateSha256()));
        out.append("\nHeartbeat:\n").append(prettyJson(heartbeat)).append('\n');
        return out.toString();
    }

    @GetMapping(value = "/endpoint", produces = MediaType.TEXT_PLAIN_VALUE)
    public String endpointQuery(@RequestParam("agent") String agent) {
        return endpoint(agent);
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
        out.append(String.format("%-10s %-22s %-30s %-14s %-22s %5s %-9s %s%n",
                "LAST SEEN", "AGENT", "TARGET", "TRUST", "PERFORMANCE", "COUNT", "STATUS", "FINDING"));
        out.append("--------------------------------------------------------------------------------------------------------------------------------\n");
        for (FindingRow row : rows) {
            out.append(String.format("%-10s %-22s %-30s %-14s %-22s %5d %-9s %s%n",
                    relativeAge(row.lastSeen(), now), trim(displayOrId(row.displayName(), row.agentId()), 22),
                    trim(row.targetHost() + ":" + row.targetPort(), 30), value(row.trustVerdict()),
                    value(row.performanceVerdict()), row.occurrenceCount(), value(row.status()), row.findingId()));
        }
        return out.toString();
    }

    @GetMapping(value = "/findings/{findingId}", produces = MediaType.TEXT_PLAIN_VALUE)
    public String finding(@PathVariable String findingId) {
        List<FindingDetail> rows = jdbc.query("""
                SELECT f.finding_id, f.finding_key, f.message_id, f.agent_id, a.display_name,
                       f.target_host, f.target_port, f.observed_from, f.observed_to,
                       f.performance_verdict, f.trust_verdict, f.evidence_root,
                       f.first_seen, f.last_seen, f.occurrence_count, f.status,
                       f.changes::text, f.rule_set::text, f.payload::text
                FROM findings f
                JOIN agents a ON a.agent_id=f.agent_id
                WHERE f.finding_id=?
                """, (rs, n) -> new FindingDetail(
                rs.getString("finding_id"), rs.getString("finding_key"), rs.getString("message_id"),
                rs.getString("agent_id"), rs.getString("display_name"), rs.getString("target_host"),
                rs.getInt("target_port"), timestampToInstant(rs.getTimestamp("observed_from")),
                timestampToInstant(rs.getTimestamp("observed_to")), rs.getString("performance_verdict"),
                rs.getString("trust_verdict"), rs.getString("evidence_root"),
                timestampToInstant(rs.getTimestamp("first_seen")), timestampToInstant(rs.getTimestamp("last_seen")),
                rs.getLong("occurrence_count"), rs.getString("status"), rs.getString("changes"),
                rs.getString("rule_set"), rs.getString("payload")), findingId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "finding not found");

        FindingDetail row = rows.getFirst();
        StringBuilder out = new StringBuilder();
        line(out, "Finding", row.findingId());
        line(out, "Finding key", row.findingKey());
        line(out, "Agent", displayOrId(row.displayName(), row.agentId()) + " (" + row.agentId() + ")");
        line(out, "Target", row.targetHost() + ":" + row.targetPort());
        line(out, "Trust", value(row.trustVerdict()));
        line(out, "Performance", value(row.performanceVerdict()));
        line(out, "Status", value(row.status()));
        line(out, "Occurrences", Long.toString(row.occurrenceCount()));
        line(out, "First seen", instant(row.firstSeen()));
        line(out, "Last seen", instant(row.lastSeen()));
        line(out, "Observed from", instant(row.observedFrom()));
        line(out, "Observed to", instant(row.observedTo()));
        line(out, "Evidence root", valueRaw(row.evidenceRoot()));
        line(out, "Message ID", valueRaw(row.messageId()));
        out.append("\nChanges:\n").append(prettyJson(parseJson(row.changes()))).append('\n');
        out.append("\nRule set:\n").append(prettyJson(parseJson(row.ruleSet()))).append('\n');
        out.append("\nPayload:\n").append(prettyJson(parseJson(row.payload()))).append('\n');
        return out.toString();
    }

    @GetMapping(value = "/finding", produces = MediaType.TEXT_PLAIN_VALUE)
    public String findingQuery(@RequestParam("id") String id) {
        return finding(id);
    }

    private JsonNode parseJson(String json) {
        if (json == null || json.isBlank()) return mapper.createObjectNode();
        try { return mapper.readTree(json); } catch (Exception ignored) { return mapper.createObjectNode(); }
    }

    private String prettyJson(JsonNode node) {
        try { return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(node); }
        catch (Exception ignored) { return node.toString(); }
    }

    private static String platform(EndpointRow row, JsonNode heartbeat) {
        if (row.agentOs() != null && !row.agentOs().isBlank()) {
            return row.agentArch() == null || row.agentArch().isBlank() ? row.agentOs() : row.agentOs() + "/" + row.agentArch();
        }
        String direct = firstText(heartbeat, "platform", "os");
        String arch = firstText(heartbeat, "arch", "architecture");
        if (!"-".equals(direct) && !"-".equals(arch) && !direct.contains("/")) return direct + "/" + arch;
        return direct;
    }

    private String features(String raw) {
        if (raw == null || raw.isBlank()) return "-";
        JsonNode node = parseJson(raw);
        if (!node.isArray() || node.isEmpty()) return "-";
        StringBuilder out = new StringBuilder();
        for (JsonNode item : node) {
            if (!item.isTextual()) continue;
            if (!out.isEmpty()) out.append(", ");
            out.append(item.asText());
        }
        return out.isEmpty() ? "-" : out.toString();
    }

    private static String integer(Integer value) { return value == null ? "-" : value.toString(); }

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

    private String endpointStatus(EndpointRow row, Instant now) {
        if (!"ACTIVE".equalsIgnoreCase(row.enrollmentStatus())) return "REVOKED";
        if (row.lastSeenAt() == null) return "NEVER_SEEN";
        Duration age = Duration.between(row.lastSeenAt(), now);
        if (age.isNegative() || age.compareTo(liveness.onlineThreshold()) <= 0) return "ONLINE";
        if (age.compareTo(liveness.offlineThreshold()) <= 0) return "STALE";
        return "OFFLINE";
    }

    private static String agentName(EndpointRow row) { return displayOrId(row.displayName(), row.agentId()); }
    private static String displayOrId(String displayName, String id) { return displayName == null || displayName.isBlank() ? id : displayName; }
    private static String value(String s) { return s == null || s.isBlank() ? "-" : s.toUpperCase(Locale.ROOT); }
    private static String valueRaw(String s) { return s == null || s.isBlank() ? "-" : s; }
    private static String trim(String s, int width) { return s == null ? "-" : s.length() <= width ? s : s.substring(0, width - 1) + "…"; }
    private static String instant(Instant instant) { return instant == null ? "-" : instant.toString(); }

    private static void line(StringBuilder out, String label, String value) {
        out.append(String.format("%-19s %s%n", label + ":", valueRaw(value)));
    }

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

    private record EndpointRow(String agentId, String displayName, String enrollmentStatus, Instant lastSeenAt,
                               String heartbeatPayload, String agentVersion, String agentBuildId,
                               String agentOs, String agentArch) {}
    private record EndpointDetail(String agentId, String fleetId, String displayName, String certificateSha256,
                                  String enrollmentStatus, long lastSequence, Instant enrolledAt, Instant lastSeenAt,
                                  String heartbeatPayload, String agentVersion, String agentBuildId, String agentGitCommit,
                                  String agentOs, String agentArch, String agentArtifactSha256,
                                  Integer agentProtocolVersion, Integer agentSchemaVersion,
                                  String agentFeatures, Instant buildReportedAt) {}
    private record FindingRow(String findingId, String agentId, String displayName, String targetHost, int targetPort,
                              String trustVerdict, String performanceVerdict, long occurrenceCount, String status, Instant lastSeen) {}
    private record FindingDetail(String findingId, String findingKey, String messageId, String agentId, String displayName,
                                 String targetHost, int targetPort, Instant observedFrom, Instant observedTo,
                                 String performanceVerdict, String trustVerdict, String evidenceRoot,
                                 Instant firstSeen, Instant lastSeen, long occurrenceCount, String status,
                                 String changes, String ruleSet, String payload) {}
    private record Summary(long total, long active, long suspicious) {}
}
