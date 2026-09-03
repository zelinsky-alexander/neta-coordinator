package dev.neta.coordinator.ingest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.config.CoordinatorProperties;
import dev.neta.coordinator.config.CoordinatorStorageProperties;
import dev.neta.coordinator.protocol.EnvelopeValidator;
import dev.neta.coordinator.protocol.MessageEnvelope;
import dev.neta.coordinator.protocol.MessageType;
import dev.neta.coordinator.protocol.ProtocolException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MessageIngestService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final EnvelopeValidator validator;
    private final CoordinatorProperties properties;
    private final CoordinatorStorageProperties storage;

    public MessageIngestService(JdbcTemplate jdbc, ObjectMapper mapper, EnvelopeValidator validator,
                                CoordinatorProperties properties, CoordinatorStorageProperties storage) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.validator = validator;
        this.properties = properties;
        this.storage = storage;
    }

    @Transactional
    public IngestResult ingest(MessageEnvelope envelope, String peerCertificateSha256) {
        validator.validate(envelope);
        var agents = jdbc.query("SELECT certificate_sha256,status,last_sequence,certificate_not_before,certificate_not_after FROM agents WHERE agent_id=? FOR UPDATE",
                (rs, n) -> new AgentState(rs.getString(1), rs.getString(2), rs.getLong(3),
                        toInstant(rs.getTimestamp(4)), toInstant(rs.getTimestamp(5))), envelope.agentId());
        if (agents.size() != 1 || !"ACTIVE".equals(agents.getFirst().status()))
            throw ProtocolException.unauthorized("agent is not active or registered");
        AgentState agent = agents.getFirst();
        Instant now = Instant.now();
        if (agent.certificateNotBefore() != null && now.isBefore(agent.certificateNotBefore()))
            throw ProtocolException.unauthorized("enrolled agent certificate is not yet valid");
        if (agent.certificateNotAfter() != null && !now.isBefore(agent.certificateNotAfter()))
            throw ProtocolException.unauthorized("enrolled agent certificate is expired");
        if (properties.security().requireClientCertificate()) {
            if (peerCertificateSha256 == null) throw ProtocolException.unauthorized("client certificate is required");
            if (!agent.certificateSha256().equalsIgnoreCase(peerCertificateSha256))
                throw ProtocolException.unauthorized("client certificate does not match enrolled agent");
        } else if (peerCertificateSha256 != null && !agent.certificateSha256().equalsIgnoreCase(peerCertificateSha256)) {
            throw ProtocolException.unauthorized("client certificate does not match enrolled agent");
        }
        if (envelope.sequence() <= agent.lastSequence())
            throw ProtocolException.conflict("sequence is not newer than the last accepted message");

        final boolean heartbeat = envelope.messageType() == MessageType.HEARTBEAT;
        if (!heartbeat || storage.retainHeartbeats()) persistProtocolMessage(envelope);

        persistTypedPayload(envelope);
        persistContact(envelope);
        if (heartbeat) {
            jdbc.update("UPDATE agents SET last_sequence=?, last_seen_at=now(), last_heartbeat_payload=CAST(? AS jsonb) WHERE agent_id=?",
                    envelope.sequence(), json(envelope.payload()), envelope.agentId());
        } else {
            jdbc.update("UPDATE agents SET last_sequence=?, last_seen_at=now() WHERE agent_id=?",
                    envelope.sequence(), envelope.agentId());
        }

        if (!heartbeat || storage.auditHeartbeats()) {
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,message_id,details) VALUES ('MESSAGE_ACCEPTED',?,?,CAST(? AS jsonb))",
                    envelope.agentId(), envelope.messageId(), json(Map.of("message_type", envelope.messageType().wireName())));
        }
        return new IngestResult(envelope.messageId(), "ACCEPTED", Instant.now());
    }

    private void persistContact(MessageEnvelope envelope) {
        jdbc.update("""
                INSERT INTO endpoint_contact_history(agent_id,message_type,sequence,message_id,contact_at)
                VALUES (?,?,?,?,now())
                ON CONFLICT (agent_id,sequence) DO NOTHING
                """, envelope.agentId(), envelope.messageType().wireName(), envelope.sequence(), envelope.messageId());
    }

    private void persistProtocolMessage(MessageEnvelope envelope) {
        try {
            jdbc.update("INSERT INTO protocol_messages(agent_id,message_id,protocol,schema_version,message_type,created_at,expires_at,sequence,correlation_id,payload_hash,payload,signature) VALUES (?,?,?,?,?,?,?,?,?,?,CAST(? AS jsonb),CAST(? AS jsonb))",
                    envelope.agentId(), envelope.messageId(), envelope.protocol(), envelope.schemaVersion(), envelope.messageType().wireName(),
                    Timestamp.from(envelope.createdAt()), Timestamp.from(envelope.expiresAt()), envelope.sequence(), envelope.correlationId(), envelope.payloadHash(),
                    json(envelope.payload()), json(envelope.signature()));
        } catch (DuplicateKeyException e) {
            throw ProtocolException.conflict("duplicate message_id or sequence");
        }
    }

    private void persistTypedPayload(MessageEnvelope e) {
        JsonNode p = e.payload();
        if (e.messageType() == MessageType.FINDING_ANNOUNCEMENT) {
            JsonNode target = p.path("target");
            String host = text(target, "host");
            int port = target.path("port").asInt(-1);
            String findingId = text(p, "finding_id");
            if (findingId == null || findingId.isBlank())
                throw ProtocolException.badRequest("FindingAnnouncement.finding_id is required");
            if (host == null || port < 1 || port > 65535)
                throw ProtocolException.badRequest("FindingAnnouncement.target host/port are required");

            String findingKey = text(p, "finding_key");
            if (findingKey == null || findingKey.isBlank()) {
                findingKey = host + ":" + port + "|" + nullSafe(text(p, "performance_verdict")) + "|" + nullSafe(text(p, "trust_verdict"));
            }

            jdbc.update("""
                    UPDATE findings SET finding_key=?
                    WHERE agent_id=? AND finding_id=? AND finding_key<>?
                      AND NOT EXISTS (SELECT 1 FROM findings other WHERE other.agent_id=? AND other.finding_key=? AND other.finding_id<>?)
                    """, findingKey, e.agentId(), findingId, findingKey, e.agentId(), findingKey, findingId);

            jdbc.update("""
                    INSERT INTO findings(
                        finding_id,finding_key,message_id,agent_id,target_host,target_port,
                        observed_from,observed_to,changes,performance_verdict,trust_verdict,
                        rule_set,evidence_root,payload,first_seen,last_seen,occurrence_count,status)
                    VALUES (?,?,?,?,?,?,?, ?,CAST(? AS jsonb),?,?,CAST(? AS jsonb),?,CAST(? AS jsonb),now(),now(),1,'ACTIVE')
                    ON CONFLICT (agent_id,finding_key) DO UPDATE SET
                        message_id=EXCLUDED.message_id,
                        observed_from=COALESCE(findings.observed_from,EXCLUDED.observed_from),
                        observed_to=COALESCE(EXCLUDED.observed_to,findings.observed_to),
                        changes=EXCLUDED.changes,
                        performance_verdict=EXCLUDED.performance_verdict,
                        trust_verdict=EXCLUDED.trust_verdict,
                        rule_set=EXCLUDED.rule_set,
                        evidence_root=EXCLUDED.evidence_root,
                        payload=EXCLUDED.payload,
                        last_seen=now(), occurrence_count=findings.occurrence_count+1, status='ACTIVE'
                    """,
                    findingId, findingKey, e.messageId(), e.agentId(), host, port,
                    timestamp(p.path("observation_window").path("from")), timestamp(p.path("observation_window").path("to")),
                    json(p.path("changes")), text(p,"performance_verdict"), text(p,"trust_verdict"),
                    json(p.path("rule_set")), text(p,"evidence_root"), json(p));
        } else if (e.messageType() == MessageType.CORROBORATION_RESPONSE) {
            String requestId = text(p,"request_id");
            Integer exists = jdbc.queryForObject("SELECT count(*) FROM corroboration_requests WHERE request_id=?", Integer.class, requestId);
            if (exists == null || exists == 0) throw ProtocolException.conflict("corroboration request is unknown");
            try {
                jdbc.update("INSERT INTO corroboration_responses(request_id,agent_id,message_id,status,observations,evidence_root) VALUES (?,?,?,?,CAST(? AS jsonb),?)",
                        requestId, e.agentId(), e.messageId(), text(p,"status"), json(p.path("observations")), text(p,"evidence_root"));
            } catch (DuplicateKeyException ex) {
                throw ProtocolException.conflict("agent already responded to this corroboration request");
            }
        } else if (e.messageType() == MessageType.EVIDENCE_SUMMARY) {
            jdbc.update("INSERT INTO evidence_summaries(agent_id,message_id,correlation_id,evidence_root,summary) VALUES (?,?,?,?,CAST(? AS jsonb))",
                    e.agentId(), e.messageId(), e.correlationId(), text(p,"evidence_root"), json(p));
        }
    }

    private String json(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (JsonProcessingException ex) { throw new IllegalArgumentException("message cannot be serialized", ex); }
    }
    private static String text(JsonNode node, String field) { JsonNode v = node.path(field); return v.isTextual() ? v.asText() : null; }
    private static String nullSafe(String value) { return value == null ? "" : value; }
    private static Timestamp timestamp(JsonNode node) {
        if (!node.isTextual() || node.asText().isBlank()) return null;
        try { return Timestamp.from(Instant.parse(node.asText())); }
        catch (RuntimeException e) { throw ProtocolException.badRequest("invalid observation timestamp"); }
    }
    private static Instant toInstant(Timestamp ts) { return ts == null ? null : ts.toInstant(); }

    private record AgentState(String certificateSha256, String status, long lastSequence,
                              Instant certificateNotBefore, Instant certificateNotAfter) {}
    public record IngestResult(String messageId, String status, Instant receivedAt) {}
}
