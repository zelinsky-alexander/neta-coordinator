package dev.neta.coordinator.ingest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.config.CoordinatorProperties;
import dev.neta.coordinator.protocol.EnvelopeValidator;
import dev.neta.coordinator.protocol.MessageEnvelope;
import dev.neta.coordinator.protocol.MessageType;
import dev.neta.coordinator.protocol.ProtocolException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
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

    public MessageIngestService(JdbcTemplate jdbc, ObjectMapper mapper, EnvelopeValidator validator, CoordinatorProperties properties) {
        this.jdbc = jdbc; this.mapper = mapper; this.validator = validator; this.properties = properties;
    }

    @Transactional
    public IngestResult ingest(MessageEnvelope envelope, String peerCertificateSha256) {
        validator.validate(envelope);
        var agents = jdbc.query("SELECT certificate_sha256,status,last_sequence FROM agents WHERE agent_id=? FOR UPDATE",
                (rs, n) -> new AgentState(rs.getString(1), rs.getString(2), rs.getLong(3)), envelope.agentId());
        if (agents.size() != 1 || !"ACTIVE".equals(agents.getFirst().status())) throw ProtocolException.unauthorized("agent is not active or registered");
        AgentState agent = agents.getFirst();
        if (properties.security().requireClientCertificate()) {
            if (peerCertificateSha256 == null) throw ProtocolException.unauthorized("client certificate is required");
            if (!agent.certificateSha256().equalsIgnoreCase(peerCertificateSha256)) throw ProtocolException.unauthorized("client certificate does not match enrolled agent");
        } else if (peerCertificateSha256 != null && !agent.certificateSha256().equalsIgnoreCase(peerCertificateSha256)) {
            throw ProtocolException.unauthorized("client certificate does not match enrolled agent");
        }
        if (envelope.sequence() <= agent.lastSequence()) throw ProtocolException.conflict("sequence is not newer than the last accepted message");
        try {
            jdbc.update("INSERT INTO protocol_messages(agent_id,message_id,protocol,schema_version,message_type,created_at,expires_at,sequence,correlation_id,payload_hash,payload,signature) VALUES (?,?,?,?,?,?,?,?,?,?,CAST(? AS jsonb),CAST(? AS jsonb))",
                    envelope.agentId(), envelope.messageId(), envelope.protocol(), envelope.schemaVersion(), envelope.messageType().wireName(),
                    Timestamp.from(envelope.createdAt()), Timestamp.from(envelope.expiresAt()), envelope.sequence(), envelope.correlationId(), envelope.payloadHash(),
                    json(envelope.payload()), json(envelope.signature()));
        } catch (DuplicateKeyException e) { throw ProtocolException.conflict("duplicate message_id or sequence"); }
        persistTypedPayload(envelope);
        jdbc.update("UPDATE agents SET last_sequence=?, last_seen_at=now() WHERE agent_id=?", envelope.sequence(), envelope.agentId());
        jdbc.update("INSERT INTO audit_events(event_type,agent_id,message_id,details) VALUES ('MESSAGE_ACCEPTED',?,?,CAST(? AS jsonb))",
                envelope.agentId(), envelope.messageId(), json(Map.of("message_type", envelope.messageType().wireName())));
        return new IngestResult(envelope.messageId(), "ACCEPTED", Instant.now());
    }

    private void persistTypedPayload(MessageEnvelope e) {
        JsonNode p = e.payload();
        if (e.messageType() == MessageType.FINDING_ANNOUNCEMENT) {
            JsonNode target = p.path("target");
            String host = text(target, "host");
            int port = target.path("port").asInt(-1);
            if (host == null || port < 1 || port > 65535) throw ProtocolException.badRequest("FindingAnnouncement.target host/port are required");
            try {
                jdbc.update("INSERT INTO findings(finding_id,message_id,agent_id,target_host,target_port,observed_from,observed_to,changes,performance_verdict,trust_verdict,rule_set,evidence_root,payload) VALUES (?,?,?,?,?,?,?,CAST(? AS jsonb),?,?,CAST(? AS jsonb),?,CAST(? AS jsonb))",
                        text(p,"finding_id"), e.messageId(), e.agentId(), host, port,
                        timestamp(p.path("observation_window").path("from")), timestamp(p.path("observation_window").path("to")),
                        json(p.path("changes")), text(p,"performance_verdict"), text(p,"trust_verdict"), json(p.path("rule_set")), text(p,"evidence_root"), json(p));
            } catch (DuplicateKeyException ex) { throw ProtocolException.conflict("finding_id already exists"); }
        } else if (e.messageType() == MessageType.CORROBORATION_RESPONSE) {
            String requestId = text(p,"request_id");
            Integer exists = jdbc.queryForObject("SELECT count(*) FROM corroboration_requests WHERE request_id=?", Integer.class, requestId);
            if (exists == null || exists == 0) throw ProtocolException.conflict("corroboration request is unknown");
            try {
                jdbc.update("INSERT INTO corroboration_responses(request_id,agent_id,message_id,status,observations,evidence_root) VALUES (?,?,?,?,CAST(? AS jsonb),?)",
                        requestId, e.agentId(), e.messageId(), text(p,"status"), json(p.path("observations")), text(p,"evidence_root"));
            } catch (DuplicateKeyException ex) { throw ProtocolException.conflict("agent already responded to this corroboration request"); }
        } else if (e.messageType() == MessageType.EVIDENCE_SUMMARY) {
            jdbc.update("INSERT INTO evidence_summaries(agent_id,message_id,correlation_id,evidence_root,summary) VALUES (?,?,?,?,CAST(? AS jsonb))",
                    e.agentId(), e.messageId(), e.correlationId(), text(p,"evidence_root"), json(p));
        }
    }

    private String json(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (JsonProcessingException ex) { throw new IllegalArgumentException("message cannot be serialized", ex); }
    }
    private static String text(JsonNode node, String field) { JsonNode v=node.path(field); return v.isTextual() ? v.asText() : null; }
    private static Timestamp timestamp(JsonNode node) {
        if (!node.isTextual() || node.asText().isBlank()) return null;
        try { return Timestamp.from(Instant.parse(node.asText())); } catch (RuntimeException e) { throw ProtocolException.badRequest("invalid observation timestamp"); }
    }

    private record AgentState(String certificateSha256, String status, long lastSequence) {}
    public record IngestResult(String messageId, String status, Instant receivedAt) {}
}
