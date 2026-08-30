package dev.neta.coordinator.enrollment;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.config.CoordinatorProperties;
import dev.neta.coordinator.protocol.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class EnrollmentService implements ApplicationRunner {
    private final JdbcTemplate jdbc;
    private final CoordinatorProperties properties;
    private final ObjectMapper mapper;

    public EnrollmentService(JdbcTemplate jdbc, CoordinatorProperties properties, ObjectMapper mapper) {
        this.jdbc = jdbc; this.properties = properties; this.mapper = mapper;
    }

    @Override public void run(ApplicationArguments args) {
        String token = properties.bootstrapEnrollmentToken();
        if (token == null || token.isBlank()) return;
        jdbc.update("INSERT INTO enrollment_tokens(token_id,fleet_id,token_hash,expires_at) VALUES (?,?,?,?) ON CONFLICT(token_hash) DO NOTHING",
                UUID.randomUUID(), properties.fleetId(), tokenHash(token), Timestamp.from(Instant.now().plus(properties.bootstrapTokenTtl())));
    }

    @Transactional
    public EnrollmentResponse enroll(EnrollmentRequest request) {
        if (!properties.fleetId().equals(request.fleetId())) throw ProtocolException.unauthorized("fleet is not authorized");
        String tokenHash = tokenHash(request.token());
        var rows = jdbc.query("SELECT token_id FROM enrollment_tokens WHERE fleet_id=? AND token_hash=? AND consumed_at IS NULL AND expires_at>now() FOR UPDATE",
                (rs, rowNum) -> rs.getObject("token_id", UUID.class), request.fleetId(), tokenHash);
        if (rows.size() != 1) throw ProtocolException.unauthorized("invalid or expired enrollment token");
        String fingerprint = normalizeFingerprint(request.certificateSha256());
        String agentId = "AGENT-" + UUID.randomUUID();
        jdbc.update("INSERT INTO agents(agent_id,fleet_id,display_name,certificate_sha256,status) VALUES (?,?,?,?, 'ACTIVE')",
                agentId, request.fleetId(), request.displayName(), fingerprint);
        jdbc.update("UPDATE enrollment_tokens SET consumed_at=now(), consumed_by_agent_id=? WHERE token_id=?", agentId, rows.getFirst());
        audit("AGENT_ENROLLED", agentId, Map.of("fleet_id", request.fleetId(), "certificate_sha256", fingerprint));
        return new EnrollmentResponse(agentId, request.fleetId(), "ACTIVE", Map.of("protocol", "neta-agent/1", "schema_version", 1));
    }

    private void audit(String type, String agentId, Map<String, Object> details) {
        try {
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES (?,?,CAST(? AS jsonb))", type, agentId, mapper.writeValueAsString(details));
        } catch (JsonProcessingException e) { throw new IllegalStateException("audit serialization failed", e); }
    }

    static String tokenHash(String token) {
        if (token == null || token.isBlank()) throw ProtocolException.unauthorized("enrollment token is required");
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 is unavailable", impossible); }
    }

    static String normalizeFingerprint(String value) {
        if (value == null || !value.matches("(?i)sha256:[0-9a-f]{64}")) throw ProtocolException.badRequest("certificate_sha256 must be sha256:<64 hex chars>");
        return value.toLowerCase();
    }

    public record EnrollmentRequest(String fleetId, String token, String displayName, String certificateSha256) {}
    public record EnrollmentResponse(String agentId, String fleetId, String status, Map<String,Object> policy) {}
}
