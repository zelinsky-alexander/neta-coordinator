package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.enrollment.CertificateIssuer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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
public class CertificateOperatorController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";

    private final JdbcTemplate jdbc;
    private final CertificateIssuer issuer;
    private final ObjectMapper mapper;
    private final String adminToken;
    private final Duration warningWindow;
    private final Duration criticalWindow;

    public CertificateOperatorController(
            JdbcTemplate jdbc,
            CertificateIssuer issuer,
            ObjectMapper mapper,
            @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken,
            @Value("${NETA_CERTIFICATE_WARNING_WINDOW:P30D}") Duration warningWindow,
            @Value("${NETA_CERTIFICATE_CRITICAL_WINDOW:P7D}") Duration criticalWindow) {
        this.jdbc = jdbc;
        this.issuer = issuer;
        this.mapper = mapper;
        this.adminToken = adminToken == null ? "" : adminToken;
        this.warningWindow = warningWindow;
        this.criticalWindow = criticalWindow;
        if (warningWindow.isNegative() || warningWindow.isZero())
            throw new IllegalArgumentException("certificate warning window must be positive");
        if (criticalWindow.isNegative() || criticalWindow.isZero() || criticalWindow.compareTo(warningWindow) > 0)
            throw new IllegalArgumentException("certificate critical window must be positive and <= warning window");
    }

    @GetMapping(value = "/certificates", produces = MediaType.TEXT_PLAIN_VALUE)
    public String certificates(@RequestParam(value = "expiring", required = false) String expiring) {
        Instant now = Instant.now();
        Duration filter = expiring == null || expiring.isBlank() ? null : parseDuration(expiring);
        List<CertificateRow> rows = loadCertificates();
        StringBuilder out = new StringBuilder();
        out.append("NETA Agent Certificates\n");
        out.append("====================================================================================================\n");
        out.append(String.format("%-24s %-10s %-12s %-25s %s%n", "AGENT", "STATE", "REMAINING", "NOT AFTER", "FINGERPRINT"));
        out.append("----------------------------------------------------------------------------------------------------\n");
        for (CertificateRow row : rows) {
            if (filter != null && !within(row.notAfter(), now, filter)) continue;
            out.append(String.format("%-24s %-10s %-12s %-25s %s%n",
                    trim(display(row), 24), lifecycle(row, now), remaining(row.notAfter(), now),
                    instant(row.notAfter()), row.fingerprint()));
        }
        out.append("\nPolicy\n");
        out.append("---------------------------------\n");
        out.append("Warning window:   ").append(warningWindow).append('\n');
        out.append("Critical window:  ").append(criticalWindow).append('\n');
        return out.toString();
    }

    @GetMapping(value = "/certificate-summary", produces = MediaType.TEXT_PLAIN_VALUE)
    public String summary() {
        Instant now = Instant.now();
        int valid = 0, expiring = 0, critical = 0, expired = 0, unknown = 0;
        for (CertificateRow row : loadCertificates()) {
            if (!"ACTIVE".equals(row.agentStatus())) continue;
            switch (lifecycle(row, now)) {
                case "VALID" -> valid++;
                case "EXPIRING" -> expiring++;
                case "CRITICAL" -> critical++;
                case "EXPIRED" -> expired++;
                default -> unknown++;
            }
        }
        return String.format("Certificates%n  Valid          %d%n  Expiring       %d%n  Critical       %d%n  Expired        %d%n  Unknown        %d%n",
                valid, expiring, critical, expired, unknown);
    }

    @PostMapping(value = "/certificate-rotate", produces = MediaType.TEXT_PLAIN_VALUE)
    @Transactional
    public String rotate(
            @RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
            @RequestParam("agent") String agent,
            @RequestParam("csr") String csr,
            @RequestParam("reason") String reason) {
        requireAdmin(suppliedToken);
        if (reason == null || reason.isBlank() || reason.length() > 500)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason is required and must be at most 500 characters");
        CertificateRow current = resolveAgent(agent);
        if (!"ACTIVE".equals(current.agentStatus()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "agent must be ACTIVE before certificate rotation");

        var replacement = issuer.issue(current.agentId(), csr);
        if (replacement.certificateSha256().equalsIgnoreCase(current.fingerprint()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "replacement certificate fingerprint matches the active certificate");

        jdbc.update("""
                UPDATE agent_certificate_history
                SET status='RETIRED', retired_at=now(), reason=COALESCE(reason,'') || ?
                WHERE agent_id=? AND status='ACTIVE'
                """, "; rotated: " + reason, current.agentId());
        if (jdbc.update("""
                INSERT INTO agent_certificate_history(agent_id,certificate_sha256,not_before,not_after,status,reason)
                VALUES (?,?,?,?, 'ACTIVE',?)
                """, current.agentId(), replacement.certificateSha256(), Timestamp.from(replacement.notBefore()),
                Timestamp.from(replacement.notAfter()), reason) != 1)
            throw new IllegalStateException("failed to persist replacement certificate history");

        jdbc.update("""
                UPDATE agents
                SET certificate_sha256=?, certificate_not_before=?, certificate_not_after=?,
                    certificate_registered_at=now(), certificate_rotated_at=now()
                WHERE agent_id=?
                """, replacement.certificateSha256(), Timestamp.from(replacement.notBefore()),
                Timestamp.from(replacement.notAfter()), current.agentId());

        audit(current.agentId(), Map.of(
                "old_certificate_sha256", current.fingerprint(),
                "new_certificate_sha256", replacement.certificateSha256(),
                "new_not_before", replacement.notBefore().toString(),
                "new_not_after", replacement.notAfter().toString(),
                "reason", reason,
                "authorization", "operator_admin_token"));

        return "Rotated certificate for " + display(current) + " (" + current.agentId() + ").\n"
                + "Old fingerprint: " + current.fingerprint() + "\n"
                + "New fingerprint: " + replacement.certificateSha256() + "\n"
                + "Valid until:     " + replacement.notAfter() + "\n\n"
                + replacement.certificatePem()
                + replacement.issuerCertificatePem();
    }

    private List<CertificateRow> loadCertificates() {
        return jdbc.query("""
                SELECT agent_id,display_name,status,certificate_sha256,certificate_not_before,
                       certificate_not_after,certificate_rotated_at
                FROM agents
                ORDER BY COALESCE(NULLIF(display_name,''),agent_id)
                """, (rs, n) -> new CertificateRow(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                toInstant(rs.getTimestamp(5)), toInstant(rs.getTimestamp(6)), toInstant(rs.getTimestamp(7))));
    }

    private CertificateRow resolveAgent(String agent) {
        List<CertificateRow> rows = jdbc.query("""
                SELECT agent_id,display_name,status,certificate_sha256,certificate_not_before,
                       certificate_not_after,certificate_rotated_at
                FROM agents WHERE agent_id=? OR display_name=?
                ORDER BY CASE WHEN agent_id=? THEN 0 ELSE 1 END LIMIT 1
                """, (rs, n) -> new CertificateRow(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                toInstant(rs.getTimestamp(5)), toInstant(rs.getTimestamp(6)), toInstant(rs.getTimestamp(7))), agent, agent, agent);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "agent not found");
        return rows.getFirst();
    }

    private String lifecycle(CertificateRow row, Instant now) {
        if (row.notAfter() == null) return "UNKNOWN";
        if (!now.isBefore(row.notAfter())) return "EXPIRED";
        Duration left = Duration.between(now, row.notAfter());
        if (left.compareTo(criticalWindow) <= 0) return "CRITICAL";
        if (left.compareTo(warningWindow) <= 0) return "EXPIRING";
        return "VALID";
    }

    private static boolean within(Instant notAfter, Instant now, Duration window) {
        return notAfter != null && !notAfter.isAfter(now.plus(window));
    }

    private void requireAdmin(String suppliedToken) {
        if (adminToken.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "certificate rotation is disabled; configure NETA_OPERATOR_ADMIN_TOKEN");
        if (!MessageDigest.isEqual(adminToken.getBytes(StandardCharsets.UTF_8),
                (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8)))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
    }

    private void audit(String agentId, Map<String,Object> details) {
        try {
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES ('AGENT_CERTIFICATE_ROTATED',?,CAST(? AS jsonb))",
                    agentId, mapper.writeValueAsString(details));
        } catch (Exception e) { throw new IllegalStateException("failed to record certificate rotation audit event", e); }
    }

    private static Duration parseDuration(String value) {
        try {
            String v = value.trim().toLowerCase();
            if (v.matches("[0-9]+d")) return Duration.ofDays(Long.parseLong(v.substring(0, v.length()-1)));
            if (v.matches("[0-9]+h")) return Duration.ofHours(Long.parseLong(v.substring(0, v.length()-1)));
            return Duration.parse(value.toUpperCase());
        } catch (RuntimeException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid expiring duration"); }
    }
    private static Instant toInstant(Timestamp ts) { return ts == null ? null : ts.toInstant(); }
    private static String instant(Instant value) { return value == null ? "-" : value.toString(); }
    private static String display(CertificateRow row) { return row.displayName() == null || row.displayName().isBlank() ? row.agentId() : row.displayName(); }
    private static String trim(String value, int width) { return value.length() <= width ? value : value.substring(0, width - 1) + "…"; }
    private static String remaining(Instant until, Instant now) {
        if (until == null) return "-";
        if (!now.isBefore(until)) return "expired";
        long hours = Duration.between(now, until).toHours();
        return hours < 48 ? hours + " hr" : (hours / 24) + " day";
    }

    private record CertificateRow(String agentId, String displayName, String agentStatus, String fingerprint,
                                  Instant notBefore, Instant notAfter, Instant rotatedAt) {}
}
