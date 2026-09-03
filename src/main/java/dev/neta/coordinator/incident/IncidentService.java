package dev.neta.coordinator.incident;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IncidentService {
    public static final Duration GROUPING_WINDOW = Duration.ofHours(1);

    private final JdbcTemplate jdbc;

    public IncidentService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Scheduled(fixedDelayString = "${NETA_INCIDENT_SYNC_INTERVAL:PT1M}")
    @Transactional
    public void syncAll() {
        List<String> ungrouped = jdbc.query("""
                SELECT f.finding_id
                FROM findings f
                LEFT JOIN incident_findings i_f ON i_f.finding_id=f.finding_id
                WHERE i_f.finding_id IS NULL
                ORDER BY f.first_seen, f.finding_id
                """, (rs, n) -> rs.getString(1));
        for (String findingId : ungrouped) assignFinding(findingId);

        List<String> incidentIds = jdbc.query("SELECT incident_id FROM incidents", (rs, n) -> rs.getString(1));
        for (String incidentId : incidentIds) recompute(incidentId);
    }

    public void assignFinding(String findingId) {
        List<FindingRef> rows = jdbc.query("""
                SELECT finding_id, agent_id, target_host, target_port, first_seen, last_seen
                FROM findings WHERE finding_id=?
                """, (rs, n) -> new FindingRef(
                rs.getString("finding_id"), rs.getString("agent_id"), rs.getString("target_host"),
                rs.getInt("target_port"), rs.getTimestamp("first_seen").toInstant(),
                rs.getTimestamp("last_seen").toInstant()), findingId);
        if (rows.isEmpty()) return;
        FindingRef finding = rows.getFirst();

        List<String> existing = jdbc.query(
                "SELECT incident_id FROM incident_findings WHERE finding_id=?",
                (rs, n) -> rs.getString(1), findingId);
        if (!existing.isEmpty()) {
            recompute(existing.getFirst());
            return;
        }

        Instant earliestJoin = finding.firstSeen().minus(GROUPING_WINDOW);
        List<String> candidates = jdbc.query("""
                SELECT incident_id
                FROM incidents
                WHERE status='OPEN' AND agent_id=? AND target_host=? AND target_port=?
                  AND last_seen >= ?
                ORDER BY last_seen DESC
                LIMIT 1
                """, (rs, n) -> rs.getString(1), finding.agentId(), finding.targetHost(), finding.targetPort(),
                java.sql.Timestamp.from(earliestJoin));

        String incidentId;
        if (candidates.isEmpty()) {
            incidentId = incidentId(finding);
            jdbc.update("""
                    INSERT INTO incidents(incident_id,agent_id,target_host,target_port,status,first_seen,last_seen)
                    VALUES (?,?,?,?,'OPEN',?,?)
                    ON CONFLICT (incident_id) DO NOTHING
                    """, incidentId, finding.agentId(), finding.targetHost(), finding.targetPort(),
                    java.sql.Timestamp.from(finding.firstSeen()), java.sql.Timestamp.from(finding.lastSeen()));
        } else {
            incidentId = candidates.getFirst();
        }

        jdbc.update("INSERT INTO incident_findings(incident_id,finding_id) VALUES (?,?) ON CONFLICT (finding_id) DO NOTHING",
                incidentId, findingId);
        recompute(incidentId);
    }

    private void recompute(String incidentId) {
        jdbc.update("""
                UPDATE incidents i SET
                    first_seen = a.first_seen,
                    last_seen = a.last_seen,
                    finding_count = a.finding_count,
                    suspicious_count = a.suspicious_count,
                    changed_count = a.changed_count,
                    updated_at = now()
                FROM (
                    SELECT min(f.first_seen) first_seen,
                           max(f.last_seen) last_seen,
                           count(*)::integer finding_count,
                           count(*) FILTER (WHERE upper(COALESCE(f.trust_verdict,''))='SUSPICIOUS')::integer suspicious_count,
                           count(*) FILTER (WHERE upper(COALESCE(f.trust_verdict,''))='CHANGED')::integer changed_count
                    FROM incident_findings m
                    JOIN findings f ON f.finding_id=m.finding_id
                    WHERE m.incident_id=?
                ) a
                WHERE i.incident_id=?
                """, incidentId, incidentId);
    }

    private static String incidentId(FindingRef finding) {
        String seed = finding.agentId() + "|" + finding.targetHost() + "|" + finding.targetPort() + "|" + finding.findingId();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(seed.getBytes(StandardCharsets.UTF_8));
            return "INCIDENT-" + HexFormat.of().formatHex(digest, 0, 8);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private record FindingRef(String findingId, String agentId, String targetHost, int targetPort,
                              Instant firstSeen, Instant lastSeen) {}
}
