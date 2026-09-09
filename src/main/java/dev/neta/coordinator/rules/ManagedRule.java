package dev.neta.coordinator.rules;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;

public record ManagedRule(
        String id,
        long revision,
        String origin,
        String engineRuleId,
        String name,
        String category,
        String severity,
        boolean enabled,
        JsonNode parameters,
        JsonNode exclude,
        String createdBy,
        Instant createdAt) {
}
