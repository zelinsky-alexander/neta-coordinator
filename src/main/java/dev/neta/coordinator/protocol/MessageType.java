package dev.neta.coordinator.protocol;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;

public enum MessageType {
    AGENT_HELLO("AgentHello"), HEARTBEAT("Heartbeat"), FINDING_ANNOUNCEMENT("FindingAnnouncement"),
    CORROBORATION_REQUEST("CorroborationRequest"), CORROBORATION_RESPONSE("CorroborationResponse"),
    EVIDENCE_SUMMARY("EvidenceSummary"), EVIDENCE_BUNDLE("EvidenceBundle"), EVIDENCE_REQUEST("EvidenceRequest"),
    UPGRADE_PROGRESS("UpgradeProgress"), ACK("Ack"), ERROR("Error");

    private final String wireName;
    MessageType(String wireName) { this.wireName = wireName; }
    @JsonValue public String wireName() { return wireName; }
    @JsonCreator public static MessageType fromWireName(String value) {
        return Arrays.stream(values()).filter(v -> v.wireName.equals(value)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported message_type: " + value));
    }
}
