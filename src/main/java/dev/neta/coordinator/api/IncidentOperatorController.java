package dev.neta.coordinator.api;

import dev.neta.coordinator.config.CoordinatorProperties;
import dev.neta.coordinator.incident.IncidentService;
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
public class IncidentOperatorController {
    private static final int MAX_INCIDENT_LIMIT = 100;

    private final JdbcTemplate jdbc;
    private final CoordinatorProperties properties;
    private final IncidentService incidents;

    public IncidentOperatorController(JdbcTemplate jdbc, CoordinatorProperties properties, IncidentService incidents) {
        this.jdbc = jdbc;
        this.properties = properties;
        this.incidents = incidents;
    }

    @GetMapping(value = "/status", produces = MediaType.TEXT_PLAIN_VALUE)
    public String status() {
        incidents.syncAll();
        Instant now = Instant.now();
        List<AgentSeen> agents = jdbc.query("SELECT status,last_seen_at FROM agents",
                (rs, n) -> new AgentSeen(rs.getString("status"), instant(rs.getTimestamp("last_seen_at"))));

        long online = 0, stale = 0, offline = 0, neverSeen = 0, revoked = 0;
        for (AgentSeen agent : agents) {
            switch (liveness(agent, now)) {
                case "ONLINE" -> online++;
                case "STALE" -> stale++;
                case "OFFLINE" -> offline++;
                case "NEVER_SEEN" -> neverSeen++;
                case "REVOKED" -> revoked++;
                default -> { }
            }
        }

        Counts findings = jdbc.queryForObject("""
                SELECT count(*) total,
                       count(*) FILTER (WHERE status='ACTIVE') active,
                       count(*) FILTER (WHERE upper(COALESCE(trust_verdict,''))='SUSPICIOUS') suspicious,
                       count(*) FILTER (WHERE upper(COALESCE(trust_verdict,''))='CHANGED') changed
                FROM findings
                """, (rs, n) -> new Counts(rs.getLong("total"), rs.getLong("active"),
                rs.getLong("suspicious"), rs.getLong("changed")));
        IncidentCounts incidentCounts = jdbc.queryForObject("""
                SELECT count(*) total, count(*) FILTER (WHERE status='OPEN') open
                FROM incidents
                """, (rs, n) -> new IncidentCounts(rs.getLong("total"), rs.getLong("open")));
        Instant lastIngestion = jdbc.queryForObject("SELECT max(last_seen_at) FROM agents", (rs, n) -> instant(rs.getTimestamp(1)));

        if (findings == null) findings = new Counts(0, 0, 0, 0);
        if (incidentCounts == null) incidentCounts = new IncidentCounts(0, 0);

        StringBuilder out = new StringBuilder();
        out.append("NETA Fleet\n");
        out.append("=================================\n");
        out.append(String.format("Endpoints        %d%n", agents.size()));
        out.append(String.format("  Online         %d%n", online));
        out.append(String.format("  Stale          %d%n", stale));
        out.append(String.format("  Offline        %d%n", offline));
        if (neverSeen > 0) out.append(String.format("  Never seen     %d%n", neverSeen));
        if (revoked > 0) out.append(String.format("  Revoked        %d%n", revoked));
        out.append('\n');
        out.append(String.format("Findings         %d%n", findings.total()));
        out.append(String.format("  Active         %d%n", findings.active()));
        out.append(String.format("  Suspicious     %d%n", findings.suspicious()));
        out.append(String.format("  Changed        %d%n", findings.changed()));
        out.append('\n');
        out.append(String.format("Incidents        %d%n", incidentCounts.total()));
        out.append(String.format("  Open           %d%n", incidentCounts.open()));
        out.append(String.format("Grouping window  %s%n", IncidentService.GROUPING_WINDOW));
        out.append('\n');
        out.append(String.format("Last ingestion   %s%n", lastIngestion == null ? "never" : relativeAge(lastIngestion, now)));
        out.append(String.format("Coordinator      %s%n", properties.security().requireClientCertificate() ? "HEALTHY / mTLS" : "HEALTHY / non-mTLS"));
        return out.toString();
    }

    @GetMapping(value = "/incidents", produces = MediaType.TEXT_PLAIN_VALUE)
    public String incidents(@RequestParam(defaultValue = "20") int limit) {
        this.incidents.syncAll();
        int bounded = Math.max(1, Math.min(limit, MAX_INCIDENT_LIMIT));
        Instant now = Instant.now();
        List<IncidentRow> rows = jdbc.query("""
                SELECT i.incident_id,i.status,i.agent_id,a.display_name,i.target_host,i.target_port,
                       i.first_seen,i.last_seen,i.finding_count,i.suspicious_count,i.changed_count
                FROM incidents i JOIN agents a ON a.agent_id=i.agent_id
                ORDER BY i.last_seen DESC LIMIT ?
                """, (rs, n) -> new IncidentRow(
                rs.getString("incident_id"), rs.getString("status"), rs.getString("agent_id"),
                rs.getString("display_name"), rs.getString("target_host"), rs.getInt("target_port"),
                instant(rs.getTimestamp("first_seen")), instant(rs.getTimestamp("last_seen")),
                rs.getInt("finding_count"), rs.getInt("suspicious_count"), rs.getInt("changed_count")), bounded);

        StringBuilder out = new StringBuilder();
        out.append(String.format("%-10s %-8s %-22s %-30s %8s %5s %7s %s%n",
                "LAST SEEN", "STATUS", "AGENT", "TARGET", "FINDINGS", "SUSP", "CHANGED", "INCIDENT"));
        out.append("--------------------------------------------------------------------------------------------------------------------------\n");
        for (IncidentRow row : rows) {
            out.append(String.format("%-10s %-8s %-22s %-30s %8d %5d %7d %s%n",
                    relativeAge(row.lastSeen(), now), value(row.status()), trim(displayOrId(row.displayName(), row.agentId()), 22),
                    trim(row.targetHost() + ":" + row.targetPort(), 30), row.findingCount(), row.suspiciousCount(),
                    row.changedCount(), row.incidentId()));
        }
        return out.toString();
    }

    @GetMapping(value = "/incident", produces = MediaType.TEXT_PLAIN_VALUE)
    public String incident(@RequestParam("id") String id) {
        incidents.syncAll();
        List<IncidentRow> rows = jdbc.query("""
                SELECT i.incident_id,i.status,i.agent_id,a.display_name,i.target_host,i.target_port,
                       i.first_seen,i.last_seen,i.finding_count,i.suspicious_count,i.changed_count
                FROM incidents i JOIN agents a ON a.agent_id=i.agent_id
                WHERE i.incident_id=?
                """, (rs, n) -> new IncidentRow(
                rs.getString("incident_id"), rs.getString("status"), rs.getString("agent_id"),
                rs.getString("display_name"), rs.getString("target_host"), rs.getInt("target_port"),
                instant(rs.getTimestamp("first_seen")), instant(rs.getTimestamp("last_seen")),
                rs.getInt("finding_count"), rs.getInt("suspicious_count"), rs.getInt("changed_count")), id);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "incident not found");
        IncidentRow row = rows.getFirst();

        List<IncidentFinding> findings = jdbc.query("""
                SELECT f.finding_id,f.first_seen,f.last_seen,f.trust_verdict,f.performance_verdict,
                       f.occurrence_count,f.status
                FROM incident_findings m JOIN findings f ON f.finding_id=m.finding_id
                WHERE m.incident_id=? ORDER BY f.first_seen,f.finding_id
                """, (rs, n) -> new IncidentFinding(
                rs.getString("finding_id"), instant(rs.getTimestamp("first_seen")), instant(rs.getTimestamp("last_seen")),
                rs.getString("trust_verdict"), rs.getString("performance_verdict"), rs.getLong("occurrence_count"),
                rs.getString("status")), id);

        StringBuilder out = new StringBuilder();
        line(out, "Incident", row.incidentId());
        line(out, "Status", value(row.status()));
        line(out, "Agent", displayOrId(row.displayName(), row.agentId()) + " (" + row.agentId() + ")");
        line(out, "Target", row.targetHost() + ":" + row.targetPort());
        line(out, "First seen", row.firstSeen().toString());
        line(out, "Last seen", row.lastSeen().toString());
        line(out, "Findings", Integer.toString(row.findingCount()));
        line(out, "Suspicious", Integer.toString(row.suspiciousCount()));
        line(out, "Changed", Integer.toString(row.changedCount()));
        line(out, "Grouping window", IncidentService.GROUPING_WINDOW.toString());
        out.append("\nMember findings:\n");
        out.append(String.format("%-10s %-14s %-22s %5s %-9s %s%n",
                "LAST SEEN", "TRUST", "PERFORMANCE", "COUNT", "STATUS", "FINDING"));
        out.append("--------------------------------------------------------------------------------------------------\n");
        Instant now = Instant.now();
        for (IncidentFinding finding : findings) {
            out.append(String.format("%-10s %-14s %-22s %5d %-9s %s%n",
                    relativeAge(finding.lastSeen(), now), value(finding.trustVerdict()), value(finding.performanceVerdict()),
                    finding.occurrenceCount(), value(finding.status()), finding.findingId()));
        }
        return out.toString();
    }

    private String liveness(AgentSeen agent, Instant now) {
        if (!"ACTIVE".equalsIgnoreCase(agent.enrollmentStatus())) return "REVOKED";
        if (agent.lastSeen() == null) return "NEVER_SEEN";
        Duration age = Duration.between(agent.lastSeen(), now);
        if (age.compareTo(properties.liveness().onlineThreshold()) <= 0) return "ONLINE";
        if (age.compareTo(properties.liveness().offlineThreshold()) <= 0) return "STALE";
        return "OFFLINE";
    }

    private static void line(StringBuilder out, String label, String value) {
        out.append(String.format("%-18s %s%n", label + ":", value));
    }

    private static Instant instant(Timestamp timestamp) { return timestamp == null ? null : timestamp.toInstant(); }
    private static String displayOrId(String displayName, String id) { return displayName == null || displayName.isBlank() ? id : displayName; }
    private static String value(String text) { return text == null || text.isBlank() ? "-" : text.toUpperCase(Locale.ROOT); }
    private static String trim(String text, int width) { return text.length() <= width ? text : text.substring(0, width - 1) + "…"; }

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

    private record AgentSeen(String enrollmentStatus, Instant lastSeen) {}
    private record Counts(long total, long active, long suspicious, long changed) {}
    private record IncidentCounts(long total, long open) {}
    private record IncidentRow(String incidentId, String status, String agentId, String displayName,
                               String targetHost, int targetPort, Instant firstSeen, Instant lastSeen,
                               int findingCount, int suspiciousCount, int changedCount) {}
    private record IncidentFinding(String findingId, Instant firstSeen, Instant lastSeen,
                                   String trustVerdict, String performanceVerdict, long occurrenceCount, String status) {}
}
