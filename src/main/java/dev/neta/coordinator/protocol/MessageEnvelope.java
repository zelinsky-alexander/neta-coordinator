package dev.neta.coordinator.protocol;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;

public record MessageEnvelope(
        String protocol,
        @JsonProperty("schema_version") int schemaVersion,
        @JsonProperty("message_id") String messageId,
        @JsonProperty("message_type") MessageType messageType,
        @JsonProperty("agent_id") String agentId,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("expires_at") Instant expiresAt,
        long sequence,
        @JsonProperty("correlation_id") String correlationId,
        @JsonProperty("payload_hash") String payloadHash,
        JsonNode payload,
        SignatureBlock signature) {}
