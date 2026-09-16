package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CoordinatorAckContractTest {
    @Test
    void serializesReliableNapAcknowledgementFields() throws Exception {
        var receivedAt = Instant.parse("2026-09-15T18:00:00Z");
        var response = new CoordinatorController.MessageResponse(
                "neta-agent/1", 1, "Ack", 1,
                "MSG-1", 7, "AGENT-1:1", "sha256:" + "a".repeat(64),
                "ALREADY_ACCEPTED", receivedAt, null, null);

        var json = new ObjectMapper().findAndRegisterModules().valueToTree(response);

        assertEquals("neta-agent/1", json.path("protocol").asText());
        assertEquals(1, json.path("schemaVersion").asInt());
        assertEquals("Ack", json.path("messageType").asText());
        assertEquals(1, json.path("ackVersion").asInt());
        assertEquals("MSG-1", json.path("messageId").asText());
        assertEquals(7, json.path("sequence").asLong());
        assertEquals("AGENT-1:1", json.path("idempotencyKey").asText());
        assertEquals("ALREADY_ACCEPTED", json.path("status").asText());
        assertEquals(receivedAt.toString(), json.path("receivedAt").asText());
    }
}
