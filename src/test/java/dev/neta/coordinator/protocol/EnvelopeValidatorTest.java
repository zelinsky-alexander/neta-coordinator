package dev.neta.coordinator.protocol;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.config.CoordinatorProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class EnvelopeValidatorTest {
    private static final Instant NOW = Instant.parse("2026-08-30T18:00:00Z");
    private final EnvelopeValidator validator = new EnvelopeValidator(
            new CoordinatorProperties("fleet-test", "", Duration.ofHours(1), null,
                    new CoordinatorProperties.Security(true, Duration.ofMinutes(2), Duration.ofMinutes(15)), null),
            Clock.fixed(NOW, ZoneOffset.UTC));
    private final ObjectMapper mapper = new ObjectMapper();

    @Test void acceptsValidFindingEnvelope() throws Exception {
        var payload = mapper.readTree("{\"finding_id\":\"FIND-1\",\"target\":{\"host\":\"api.example\",\"port\":443},\"evidence_root\":\"sha256:x\"}");
        assertDoesNotThrow(() -> validator.validate(envelope(MessageType.FINDING_ANNOUNCEMENT, payload, NOW.minusSeconds(1), NOW.plusSeconds(60))));
    }

    @Test void rejectsExpiredMessage() throws Exception {
        var payload = mapper.readTree("{\"finding_id\":\"FIND-1\",\"target\":{\"host\":\"api.example\",\"port\":443},\"evidence_root\":\"sha256:x\"}");
        assertThrows(ProtocolException.class, () -> validator.validate(envelope(MessageType.FINDING_ANNOUNCEMENT, payload, NOW.minusSeconds(120), NOW.minusSeconds(1))));
    }

    @Test void rejectsCoordinatorOnlyMessageFromAgent() throws Exception {
        var payload = mapper.readTree("{}");
        assertThrows(ProtocolException.class, () -> validator.validate(envelope(MessageType.CORROBORATION_REQUEST, payload, NOW, NOW.plusSeconds(60))));
    }

    private MessageEnvelope envelope(MessageType type, com.fasterxml.jackson.databind.JsonNode payload, Instant created, Instant expires) {
        return new MessageEnvelope("neta-agent/1", 1, "MSG-1", type, "AGENT-1", created, expires, 1, null,
                "sha256:" + "a".repeat(64), payload, new SignatureBlock("ed25519", "key-1", "placeholder"));
    }
}
