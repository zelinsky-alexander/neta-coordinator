package dev.neta.coordinator.protocol;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgentBuildIdentityTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void oldHeartbeatWithoutBuildIdentityRemainsAcceptedByParser() {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("status", "ok");

        assertTrue(AgentBuildIdentity.from(envelope(MessageType.HEARTBEAT, payload)).isEmpty());
    }

    @Test
    void parsesCompleteBuildIdentityFromHeartbeat() {
        ObjectNode payload = mapper.createObjectNode();
        ObjectNode build = payload.putObject("build");
        build.put("version", "1.4.0");
        build.put("build_id", "20260905.1");
        build.put("git_commit", "91ad71c31e");
        build.put("os", "linux");
        build.put("arch", "arm64");
        build.put("artifact_sha256", "sha256:" + "A".repeat(64));
        build.put("protocol_version", 1);
        build.put("schema_version", 7);
        build.putArray("features").add("ebpf").add("openssl");

        AgentBuildIdentity identity = AgentBuildIdentity.from(envelope(MessageType.HEARTBEAT, payload)).orElseThrow();

        assertEquals("1.4.0", identity.version());
        assertEquals("20260905.1", identity.buildId());
        assertEquals("91ad71c31e", identity.gitCommit());
        assertEquals("linux", identity.os());
        assertEquals("arm64", identity.arch());
        assertEquals("a".repeat(64), identity.artifactSha256());
        assertEquals(1, identity.protocolVersion());
        assertEquals(7, identity.schemaVersion());
        assertEquals(2, identity.features().size());
    }

    @Test
    void acceptsBuildIdentityOnAgentHello() {
        ObjectNode payload = mapper.createObjectNode();
        ObjectNode build = payload.putObject("build");
        build.put("version", "1.4.0");
        build.put("build_id", "20260905.1");
        build.put("os", "linux");
        build.put("arch", "amd64");

        assertTrue(AgentBuildIdentity.from(envelope(MessageType.AGENT_HELLO, payload)).isPresent());
    }

    @Test
    void optionalFieldsMayBeAbsent() {
        ObjectNode payload = mapper.createObjectNode();
        ObjectNode build = payload.putObject("build");
        build.put("version", "1.4.0");
        build.put("build_id", "20260905.1");
        build.put("os", "linux");
        build.put("arch", "amd64");

        AgentBuildIdentity identity = AgentBuildIdentity.from(envelope(MessageType.HEARTBEAT, payload)).orElseThrow();

        assertNull(identity.gitCommit());
        assertNull(identity.artifactSha256());
        assertNull(identity.protocolVersion());
        assertNull(identity.schemaVersion());
        assertTrue(identity.features().isArray());
        assertTrue(identity.features().isEmpty());
    }

    @Test
    void ignoresBuildObjectOnUnrelatedMessageTypes() {
        ObjectNode payload = mapper.createObjectNode();
        payload.putObject("build").put("version", "1.4.0");

        assertFalse(AgentBuildIdentity.from(envelope(MessageType.EVIDENCE_SUMMARY, payload)).isPresent());
    }

    @Test
    void rejectsIncompleteBuildIdentity() {
        ObjectNode payload = mapper.createObjectNode();
        ObjectNode build = payload.putObject("build");
        build.put("version", "1.4.0");
        build.put("os", "linux");
        build.put("arch", "arm64");

        assertThrows(ProtocolException.class,
                () -> AgentBuildIdentity.from(envelope(MessageType.HEARTBEAT, payload)));
    }

    @Test
    void rejectsInvalidArtifactDigest() {
        ObjectNode payload = mapper.createObjectNode();
        ObjectNode build = payload.putObject("build");
        build.put("version", "1.4.0");
        build.put("build_id", "20260905.1");
        build.put("os", "linux");
        build.put("arch", "arm64");
        build.put("artifact_sha256", "not-a-digest");

        assertThrows(ProtocolException.class,
                () -> AgentBuildIdentity.from(envelope(MessageType.HEARTBEAT, payload)));
    }

    private MessageEnvelope envelope(MessageType type, ObjectNode payload) {
        Instant created = Instant.parse("2026-09-05T05:00:00Z");
        return new MessageEnvelope(
                "neta-agent/1",
                1,
                "MSG-BUILD-1",
                type,
                "AGENT-1",
                created,
                created.plusSeconds(60),
                1,
                null,
                "sha256:" + "b".repeat(64),
                payload,
                new SignatureBlock("ed25519", "key-1", "placeholder"));
    }
}
