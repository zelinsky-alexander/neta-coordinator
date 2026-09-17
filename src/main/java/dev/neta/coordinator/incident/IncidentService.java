package dev.neta.coordinator.incident;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IncidentService {
    public static final Duration GROUPING_WINDOW = Duration.ofHours(1);
    public static final String CURRENT_ACTIONABLE = "CURRENT_ACTIONABLE";
    public static final String ACTIVE_HISTORICAL = "ACTIVE_HISTORICAL";
    public static final String CANDIDATE_ONLY = "CANDIDATE_ONLY";
    public static final String ALL = "ALL";

    private final JdbcTemplate jdbc;
    private final Duration currentActionableWindow;
    private final Clock clock;

    @Autowired
    public IncidentService(
            JdbcTemplate jdbc,
            @Value("${NETA_FINDINGS_CURRENT_ACTIONABLE_WINDOW:PT24H}") Duration currentActionableWindow) {
        this(jdbc, currentActionableWindow, Clock.systemUTC());
    }

    IncidentService(JdbcTemplate jdbc, Duration currentActionableWindow, Clock clock) {
        if (currentActionableWindow.isZero() || currentActionableWindow.isNegative()) {
            throw new IllegalArgumentException("current actionable incident window must be positive");
        }
        this.jdbc = jdbc;
        this.currentActionableWindow = currentActionableWindow;
        this.clock = clock;
    }

    @Scheduled(fixedDelayString = "${NETA_INCIDENT_SYNC_INTERVAL:PT1M}")
    @Transactional
    public void syncAll() {
        List<String> ungrouped = jdbc.query("""
                SELECT f.finding_id
                FROM findings f
                LEFT JOIN incident_findings i_f ON i_f.finding_id=f.finding_id
                WHERE i_f.finding_id IS NULL
                  AND upper(COALESCE(f.status,'')) IN ('ACTIVE','CANDIDATE')
                ORDER BY f.first_seen, f.finding_id
                """, (rs, n) -> rs.getString(1));
        for (String findingId : ungrouped) assignFinding(findingId);

        List<String> incidentIds = jdbc.query(
                "SELECT incident_id FROM incidents", (rs, n) -> rs.getString(1));
        for (String incidentId : incidentIds) recompute(incidentId);
    }

    public void assignFinding(String findingId) {
        List<FindingRef> rows = jdbc.query("""
                SELECT finding_id, agent_id, target_host, target_port, subject_type, subject_id,
                       first_seen, last_seen, status
                FROM findings WHERE finding_id=?
                """, (rs, n) -> {
                    String targetHost = rs.getString("target_host");
                    Integer targetPort = rs.getObject("target_port", Integer.class);
                    String subjectType = rs.getString("subject_type");
                    String subjectId = rs.getString("subject_id");
                    String groupingHost = targetHost;
                    int groupingPort = targetPort == null ? 0 : targetPort;
                    if (groupingHost == null && subjectType != null && subjectId != null) {
                        // Generic subjects use a reserved internal grouping key. The finding
                        // itself retains its canonical subject fields and NULL target columns.
                        groupingHost = "subject:" + subjectType + ":" + subjectId;
                        groupingPort = 1;
                    }
                    return new FindingRef(
                            rs.getString("finding_id"), rs.getString("agent_id"), groupingHost,
                            groupingPort, rs.getTimestamp("first_seen").toInstant(),
                            rs.getTimestamp("last_seen").toInstant(), rs.getString("status"));
                }, findingId);
        if (rows.isEmpty()) return;
        FindingRef finding = rows.getFirst();
        if (!liveFindingStatus(finding.status())) return;
        if (finding.targetHost() == null || finding.targetPort() < 1) return;

        List<String> existing = jdbc.query(
                "SELECT incident_id FROM incident_findings WHERE finding_id=?",
                (rs, n) -> rs.getString(1), findingId);
        if (!existing.isEmpty()) {
            recompute(existing.getFirst());
            return;
        }

        Instant earliestJoin = finding.firstSeen().minus(GROUPING_WINDOW);
        // Candidate-only and historical incidents remain valid correlation containers. Do not
        // require status=OPEN here or weak findings would fragment into one incident each.
        List<String> candidates = jdbc.query("""
                SELECT incident_id
                FROM incidents
                WHERE agent_id=? AND target_host=? AND target_port=? AND last_seen>=?
                ORDER BY last_seen DESC
                LIMIT 1
                """, (rs, n) -> rs.getString(1), finding.agentId(), finding.targetHost(),
                finding.targetPort(), Timestamp.from(earliestJoin));

        String incidentId;
        if (candidates.isEmpty()) {
            incidentId = incidentId(finding);
            jdbc.update("""
                    INSERT INTO incidents(
                        incident_id,agent_id,target_host,target_port,status,population,first_seen,last_seen)
                    VALUES (?,?,?,?,'CLOSED','CANDIDATE_ONLY',?,?)
                    ON CONFLICT (incident_id) DO NOTHING
                    """, incidentId, finding.agentId(), finding.targetHost(), finding.targetPort(),
                    Timestamp.from(finding.firstSeen()), Timestamp.from(finding.lastSeen()));
        } else {
            incidentId = candidates.getFirst();
        }

        jdbc.update("""
                INSERT INTO incident_findings(incident_id,finding_id)
                VALUES (?,?) ON CONFLICT (finding_id) DO NOTHING
                """, incidentId, findingId);
        recompute(incidentId);
    }

    private void recompute(String incidentId) {
        IncidentAggregate aggregate = jdbc.queryForObject("""
                SELECT min(f.first_seen) first_seen,
                       max(f.last_seen) last_seen,
                       count(*)::integer finding_count,
                       count(*) FILTER (
                           WHERE upper(COALESCE(f.trust_verdict,''))='SUSPICIOUS')::integer suspicious_count,
                       count(*) FILTER (
                           WHERE upper(COALESCE(f.trust_verdict,''))='CHANGED')::integer changed_count,
                       count(*) FILTER (
                           WHERE upper(COALESCE(f.status,''))='ACTIVE' AND f.last_seen>=?)::integer current_count,
                       count(*) FILTER (
                           WHERE upper(COALESCE(f.status,''))='ACTIVE')::integer active_count
                FROM incident_findings m
                JOIN findings f ON f.finding_id=m.finding_id
                WHERE m.incident_id=?
                  AND upper(COALESCE(f.status,'')) IN ('ACTIVE','CANDIDATE')
                """, (rs, n) -> new IncidentAggregate(
                        rs.getTimestamp("first_seen"), rs.getTimestamp("last_seen"),
                        rs.getInt("finding_count"), rs.getInt("suspicious_count"),
                        rs.getInt("changed_count"), rs.getInt("current_count"),
                        rs.getInt("active_count")),
                Timestamp.from(clock.instant().minus(currentActionableWindow)), incidentId);

        if (aggregate == null || aggregate.findingCount() == 0) {
            jdbc.update("DELETE FROM incidents WHERE incident_id=?", incidentId);
            return;
        }

        String population = derivePopulation(aggregate.currentCount(), aggregate.activeCount());
        jdbc.update("""
                UPDATE incidents SET
                    status=?,
                    population=?,
                    first_seen=?,
                    last_seen=?,
                    finding_count=?,
                    suspicious_count=?,
                    changed_count=?,
                    updated_at=now()
                WHERE incident_id=?
                """, lifecycleStatus(population), population, aggregate.firstSeen(), aggregate.lastSeen(),
                aggregate.findingCount(), aggregate.suspiciousCount(), aggregate.changedCount(), incidentId);
    }

    static String derivePopulation(int currentActionableCount, int activeCount) {
        if (currentActionableCount > 0) return CURRENT_ACTIONABLE;
        if (activeCount > 0) return ACTIVE_HISTORICAL;
        return CANDIDATE_ONLY;
    }

    static String lifecycleStatus(String population) {
        return CURRENT_ACTIONABLE.equals(population) ? "OPEN" : "CLOSED";
    }

    static boolean liveFindingStatus(String status) {
        return "ACTIVE".equalsIgnoreCase(status) || "CANDIDATE".equalsIgnoreCase(status);
    }

    public static String normalizePopulation(String raw) {
        if (raw == null || raw.isBlank()) return CURRENT_ACTIONABLE;
        return switch (raw.trim().toUpperCase(Locale.ROOT)) {
            case "CURRENT", "CURRENT_ACTIONABLE" -> CURRENT_ACTIONABLE;
            case "HISTORICAL", "ACTIVE_HISTORICAL" -> ACTIVE_HISTORICAL;
            case "CANDIDATE", "CANDIDATES", "CANDIDATE_ONLY" -> CANDIDATE_ONLY;
            case "ANY", "ALL" -> ALL;
            default -> throw new IllegalArgumentException(
                    "incident population must be current_actionable, active_historical, candidate_only or all");
        };
    }

    private static String incidentId(FindingRef finding) {
        String seed = finding.agentId() + "|" + finding.targetHost() + "|"
                + finding.targetPort() + "|" + finding.findingId();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(seed.getBytes(StandardCharsets.UTF_8));
            return "INCIDENT-" + HexFormat.of().formatHex(digest, 0, 8);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private record FindingRef(String findingId, String agentId, String targetHost, int targetPort,
                              Instant firstSeen, Instant lastSeen, String status) {}
    private record IncidentAggregate(java.sql.Timestamp firstSeen, java.sql.Timestamp lastSeen,
                                     int findingCount, int suspiciousCount, int changedCount,
                                     int currentCount, int activeCount) {}
}
