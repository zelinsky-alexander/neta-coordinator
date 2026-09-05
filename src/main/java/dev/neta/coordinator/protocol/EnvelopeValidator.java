package dev.neta.coordinator.protocol;

import dev.neta.coordinator.config.CoordinatorProperties;
import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public final class EnvelopeValidator {
    private static final Set<MessageType> AGENT_TO_COORDINATOR = EnumSet.of(
            MessageType.AGENT_HELLO, MessageType.HEARTBEAT, MessageType.FINDING_ANNOUNCEMENT,
            MessageType.CORROBORATION_RESPONSE, MessageType.EVIDENCE_SUMMARY, MessageType.UPGRADE_PROGRESS);
    private final CoordinatorProperties properties;
    private final Clock clock;

    @Autowired
    public EnvelopeValidator(CoordinatorProperties properties) { this(properties, Clock.systemUTC()); }
    EnvelopeValidator(CoordinatorProperties properties, Clock clock) { this.properties = properties; this.clock = clock; }

    public void validate(MessageEnvelope e) {
        if (e == null) throw ProtocolException.badRequest("message body is required");
        if (!"neta-agent/1".equals(e.protocol())) throw ProtocolException.badRequest("unsupported protocol");
        if (e.schemaVersion() != 1) throw ProtocolException.badRequest("unsupported schema_version");
        requireText(e.messageId(), "message_id");
        requireText(e.agentId(), "agent_id");
        if (e.messageType() == null || !AGENT_TO_COORDINATOR.contains(e.messageType())) throw ProtocolException.badRequest("message_type is not accepted from agents");
        if (e.sequence() < 0) throw ProtocolException.badRequest("sequence must be non-negative");
        if (e.createdAt() == null || e.expiresAt() == null) throw ProtocolException.badRequest("created_at and expires_at are required");
        Instant now = clock.instant();
        if (e.expiresAt().isBefore(now) || e.expiresAt().equals(now)) throw ProtocolException.badRequest("message has expired");
        if (e.createdAt().isAfter(now.plus(properties.security().maxClockSkew()))) throw ProtocolException.badRequest("created_at is too far in the future");
        if (!e.expiresAt().isAfter(e.createdAt())) throw ProtocolException.badRequest("expires_at must be after created_at");
        if (e.expiresAt().isAfter(e.createdAt().plus(properties.security().maxMessageLifetime()))) throw ProtocolException.badRequest("message lifetime exceeds policy");
        if (e.payload() == null || !e.payload().isObject()) throw ProtocolException.badRequest("payload must be an object");
        if (e.payloadHash() == null || !e.payloadHash().matches("sha256:[0-9a-fA-F]{64}")) throw ProtocolException.badRequest("payload_hash must be sha256:<64 hex chars>");
        if (e.signature() == null) throw ProtocolException.badRequest("signature metadata is required");
        requireText(e.signature().algorithm(), "signature.algorithm");
        requireText(e.signature().keyId(), "signature.key_id");
        requireText(e.signature().value(), "signature.value");
        validatePayload(e);
    }

    private static void validatePayload(MessageEnvelope e) {
        if (e.messageType() == MessageType.FINDING_ANNOUNCEMENT) {
            requirePayloadText(e, "finding_id");
            if (!e.payload().path("target").isObject()) throw ProtocolException.badRequest("FindingAnnouncement.target is required");
            requirePayloadText(e, "evidence_root");
        } else if (e.messageType() == MessageType.CORROBORATION_RESPONSE) {
            requirePayloadText(e, "request_id");
            requirePayloadText(e, "status");
            if (e.correlationId() == null || !e.correlationId().equals(e.payload().path("request_id").asText()))
                throw ProtocolException.badRequest("correlation_id must match CorroborationResponse.request_id");
        } else if (e.messageType() == MessageType.UPGRADE_PROGRESS) {
            requirePayloadText(e, "upgrade_id");
            requirePayloadText(e, "status");
        }
    }

    private static void requirePayloadText(MessageEnvelope e, String field) {
        if (!e.payload().path(field).isTextual() || e.payload().path(field).asText().isBlank())
            throw ProtocolException.badRequest(e.messageType().wireName() + "." + field + " is required");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) throw ProtocolException.badRequest(name + " is required");
    }
}
