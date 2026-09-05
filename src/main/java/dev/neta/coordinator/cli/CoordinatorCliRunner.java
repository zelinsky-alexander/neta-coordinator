package dev.neta.coordinator.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class CoordinatorCliRunner implements ApplicationRunner {
    private static final Duration ONLINE_WINDOW = Duration.ofMinutes(2);
    private static final int DEFAULT_FINDING_LIMIT = 10;
    private static final int MAX_FINDING_LIMIT = 100;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public CoordinatorCliRunner(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    public static boolean isCliInvocation(String[] args) {
        if (args.length == 0) return false;
        return switch (args[0]) {
            case "endpoints", "findings", "help" -> true;
            default -> false;
        };
    }

    @Override
    public void run(ApplicationArguments args) {
        List<String> positional = args.getNonOptionArgs();
        if (positional.isEmpty()) return;

        switch (positional.getFirst()) {
            case "endpoints" -> printEndpoints();
            case "findings" -> printFindings(parseLimit(positional));
            case "help" -> printHelp();
            default -> {
                // Normal server startup may receive unrelated positional arguments.
            }
        }
    }

    private void printEndpoints() {
        Instant now = Instant.now();
        List<EndpointRow> rows = jdbc.query("""
                SELECT agent_id, display_name, status, last_seen_at, last_heartbeat_payload::text,
                       agent_version, agent_build_id, agent_os, agent_arch
                FROM agents
                ORDER BY COALESCE(NULLIF(display_name, ''), agent_id)
                """, (rs, rowNum) -> new EndpointRow(
                rs.getString("agent_id"),
                rs.getString("display_name"),
                rs.getString("status"),
                timestampToInstant(rs.getTimestamp("last_seen_at")),
                rs.getString("last_heartbeat_payload"),
                rs.getString("agent_version"),
                rs.getString("agent_build_id"),
                rs.getString("agent_os"),
                rs.getString("agent_arch")));

        System.out.printf("%-24s %-12s %-16s %-18s %-18s %-10s %s%n",
                "AGENT", "VERSION", "BUILD", "PLATFORM", "SITE", "STATUS", "LAST SEEN");
        System.out.println("--------------------------------------------------------------------------------------------------------------------");
        for (EndpointRow row : rows) {
            JsonNode heartbeat = parseJson(row.heartbeatPayload());
            String platform = platform(row, heartbeat);
            String site = firstText(heartbeat, "site", "region", "location");
            if ("-".equals(site)) site = nestedText(heartbeat, "network", "site");

            System.out.printf("%-24s %-12s %-16s %-18s %-18s %-10s %s%n",
                    trim(agentName(row), 24),
                    trim(valueOrDashRaw(row.agentVersion()), 12),
                    trim(valueOrDashRaw(row.agentBuildId()), 16),
                    trim(platform, 18),
                    trim(site, 18),
                    endpointStatus(row, now),
                    relativeAge(row.lastSeenAt(), now));
        }
        if (rows.isEmpty()) System.out.println("(no enrolled endpoints)");
    }

    private void printFindings(int limit) {
        FindingTotals totals = jdbc.queryForObject("""
                SELECT count(*) AS total,
                       count(*) FILTER (WHERE status='ACTIVE') AS active,
                       count(*) FILTER (WHERE trust_verdict='SUSPICIOUS') AS suspicious
                FROM findings
                """, (rs, rowNum) -> new FindingTotals(
                rs.getLong("total"), rs.getLong("active"), rs.getLong("suspicious")));

        if (totals == null) totals = new FindingTotals(0, 0, 0);
        System.out.printf("Findings: total=%d active=%d suspicious=%d%n%n",
                totals.total(), totals.active(), totals.suspicious());

        List<FindingRow> rows = jdbc.query("""
                SELECT f.finding_id, f.agent_id, a.display_name,
                       f.target_host, f.target_port,
                       f.trust_verdict, f.performance_verdict,
                       f.occurrence_count, f.status, f.last_seen
                FROM findings f
                JOIN agents a ON a.agent_id=f.agent_id
                ORDER BY f.last_seen DESC
                LIMIT ?
                """, (rs, rowNum) -> new FindingRow(
                rs.getString("finding_id"),
                rs.getString("agent_id"),
                rs.getString("display_name"),
                rs.getString("target_host"),
                rs.getInt("target_port"),
                valueOrDash(rs.getString("trust_verdict")),
                valueOrDash(rs.getString("performance_verdict")),
                rs.getLong("occurrence_count"),
                rs.getString("status"),
                timestampToInstant(rs.getTimestamp("last_seen"))), limit);

        Instant now = Instant.now();
        System.out.printf("%-10s %-20s %-28s %-13s %-13s %7s %-9s %s%n",
                "LAST SEEN", "AGENT", "TARGET", "TRUST", "PERFORMANCE", "COUNT", "STATUS", "FINDING");
        System.out.println("----------------------------------------------------------------------------------------------------------------");
        for (FindingRow row : rows) {
            String target = row.targetHost() + ":" + row.targetPort();
            String agent = row.displayName() == null || row.displayName().isBlank() ? row.agentId() : row.displayName();
            System.out.printf("%-10s %-20s %-28s %-13s %-13s %7d %-9s %s%n",
                    relativeAge(row.lastSeen(), now),
                    trim(agent, 20),
                    trim(target, 28),
                    trim(row.trustVerdict(), 13),
                    trim(row.performanceVerdict(), 13),
                    row.occurrenceCount(),
                    trim(row.status(), 9),
                    row.findingId());
        }
        if (rows.isEmpty()) System.out.println("(no findings)");
    }

    private static int parseLimit(List<String> positional) {
        if (positional.size() < 2) return DEFAULT_FINDING_LIMIT;
        try {
            int requested = Integer.parseInt(positional.get(1));
            if (requested < 1 || requested > MAX_FINDING_LIMIT) {
                throw new IllegalArgumentException("findings limit must be between 1 and " + MAX_FINDING_LIMIT);
            }
            return requested;
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("findings limit must be an integer", ex);
        }
    }

    private static void printHelp() {
        System.out.println("NETA Coordinator operator CLI");
        System.out.println("  endpoints       Show enrolled endpoints, build identity, and last-seen status");
        System.out.println("  findings [N]    Show latest findings (default 10, max 100)");
        System.out.println("  help             Show this help");
    }

    private JsonNode parseJson(String value) {
        if (value == null || value.isBlank()) return mapper.createObjectNode();
        try {
            return mapper.readTree(value);
        } catch (Exception ex) {
            return mapper.createObjectNode();
        }
    }

    private static String platform(EndpointRow row, JsonNode heartbeat) {
        if (row.agentOs() != null && !row.agentOs().isBlank()) {
            return row.agentArch() == null || row.agentArch().isBlank()
                    ? row.agentOs() : row.agentOs() + "/" + row.agentArch();
        }
        String platform = firstText(heartbeat, "platform", "os");
        if ("-".equals(platform)) platform = nestedText(heartbeat, "host", "platform");
        String architecture = firstText(heartbeat, "architecture", "arch");
        if ("-".equals(architecture)) architecture = nestedText(heartbeat, "host", "architecture");
        if ("-".equals(architecture)) architecture = nestedText(heartbeat, "host", "arch");
        if ("-".equals(platform)) return "-";
        return "-".equals(architecture) ? platform : platform + "/" + architecture;
    }

    private static String firstText(JsonNode node, String... fields) {
        for (String field : fields) {
            JsonNode value = node.path(field);
            if (value.isTextual() && !value.asText().isBlank()) return value.asText();
        }
        return "-";
    }

    private static String nestedText(JsonNode node, String parent, String child) {
        JsonNode value = node.path(parent).path(child);
        return value.isTextual() && !value.asText().isBlank() ? value.asText() : "-";
    }

    private static String endpointStatus(EndpointRow row, Instant now) {
        if (!"ACTIVE".equals(row.enrollmentStatus())) return row.enrollmentStatus();
        if (row.lastSeenAt() == null) return "OFFLINE";
        Duration age = Duration.between(row.lastSeenAt(), now);
        if (age.isNegative()) age = Duration.ZERO;
        return age.compareTo(ONLINE_WINDOW) <= 0 ? "ONLINE" : "OFFLINE";
    }

    private static String relativeAge(Instant value, Instant now) {
        if (value == null) return "never";
        Duration age = Duration.between(value, now);
        if (age.isNegative()) age = Duration.ZERO;
        long seconds = age.toSeconds();
        if (seconds < 60) return seconds + " sec";
        long minutes = age.toMinutes();
        if (minutes < 60) return minutes + " min";
        long hours = age.toHours();
        if (hours < 24) return hours + " h";
        return age.toDays() + " d";
    }

    private static String agentName(EndpointRow row) {
        return row.displayName() == null || row.displayName().isBlank() ? row.agentId() : row.displayName();
    }

    private static String valueOrDash(String value) {
        return value == null || value.isBlank() ? "-" : value.toUpperCase(Locale.ROOT);
    }

    private static String valueOrDashRaw(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private static String trim(String value, int width) {
        if (value == null) return "-";
        if (value.length() <= width) return value;
        return value.substring(0, Math.max(1, width - 1)) + "…";
    }

    private static Instant timestampToInstant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    private record EndpointRow(String agentId, String displayName, String enrollmentStatus,
                               Instant lastSeenAt, String heartbeatPayload, String agentVersion,
                               String agentBuildId, String agentOs, String agentArch) {}

    private record FindingTotals(long total, long active, long suspicious) {}

    private record FindingRow(String findingId, String agentId, String displayName,
                              String targetHost, int targetPort, String trustVerdict,
                              String performanceVerdict, long occurrenceCount,
                              String status, Instant lastSeen) {}
}
