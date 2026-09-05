package dev.neta.coordinator.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.util.Locale;
import java.util.Optional;

/**
 * Exact agent runtime build identity reported in AgentHello or Heartbeat payload.build.
 * The build object is optional for backward compatibility with existing agents.
 */
public record AgentBuildIdentity(
        String version,
        String buildId,
        String gitCommit,
        String os,
        String arch,
        String artifactSha256,
        Integer protocolVersion,
        Integer schemaVersion,
        JsonNode features) {

    private static final int MAX_SHORT_TEXT = 128;
    private static final int MAX_VERSION_TEXT = 256;

    public static Optional<AgentBuildIdentity> from(MessageEnvelope envelope) {
        if (envelope == null || (envelope.messageType() != MessageType.AGENT_HELLO
                && envelope.messageType() != MessageType.HEARTBEAT)) {
            return Optional.empty();
        }

        JsonNode build = envelope.payload().get("build");
        if (build == null || build.isNull()) return Optional.empty();
        if (!build.isObject()) throw ProtocolException.badRequest("payload.build must be an object");

        String version = requiredText(build, "version", MAX_VERSION_TEXT);
        String buildId = requiredText(build, "build_id", MAX_SHORT_TEXT);
        String os = requiredText(build, "os", MAX_SHORT_TEXT);
        String arch = requiredText(build, "arch", MAX_SHORT_TEXT);
        String gitCommit = optionalText(build, "git_commit", MAX_SHORT_TEXT);
        String artifactSha256 = optionalSha256(build, "artifact_sha256");
        Integer protocolVersion = optionalNonNegativeInt(build, "protocol_version");
        Integer schemaVersion = optionalNonNegativeInt(build, "schema_version");

        JsonNode features = build.get("features");
        if (features == null || features.isNull()) {
            features = JsonNodeFactory.instance.arrayNode();
        } else if (!features.isArray()) {
            throw ProtocolException.badRequest("payload.build.features must be an array");
        }

        return Optional.of(new AgentBuildIdentity(version, buildId, gitCommit, os, arch,
                artifactSha256, protocolVersion, schemaVersion, features.deepCopy()));
    }

    private static String requiredText(JsonNode node, String field, int maxLength) {
        String value = optionalText(node, field, maxLength);
        if (value == null) throw ProtocolException.badRequest("payload.build." + field + " is required");
        return value;
    }

    private static String optionalText(JsonNode node, String field, int maxLength) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) return null;
        if (!value.isTextual() || value.asText().isBlank())
            throw ProtocolException.badRequest("payload.build." + field + " must be non-empty text");
        String text = value.asText();
        if (text.length() > maxLength)
            throw ProtocolException.badRequest("payload.build." + field + " is too long");
        return text;
    }

    private static String optionalSha256(JsonNode node, String field) {
        String value = optionalText(node, field, 71);
        if (value == null) return null;
        String normalized = value.toLowerCase(Locale.ROOT);
        if (normalized.startsWith("sha256:")) normalized = normalized.substring("sha256:".length());
        if (!normalized.matches("[0-9a-f]{64}"))
            throw ProtocolException.badRequest("payload.build." + field + " must be a SHA-256 digest");
        return normalized;
    }

    private static Integer optionalNonNegativeInt(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) return null;
        if (!value.canConvertToInt() || !value.isIntegralNumber() || value.intValue() < 0)
            throw ProtocolException.badRequest("payload.build." + field + " must be a non-negative integer");
        return value.intValue();
    }
}
