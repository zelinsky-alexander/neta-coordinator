package dev.neta.coordinator.api;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import dev.neta.coordinator.enrollment.EnrollmentService;
import dev.neta.coordinator.enrollment.EnrollmentService.EnrollmentRequest;
import dev.neta.coordinator.enrollment.EnrollmentService.EnrollmentResponse;
import dev.neta.coordinator.ingest.MessageIngestService;
import dev.neta.coordinator.ingest.MessageIngestService.IngestResult;
import dev.neta.coordinator.protocol.MessageEnvelope;
import dev.neta.coordinator.protocol.MessageType;
import dev.neta.coordinator.rules.RuleConvergenceService;
import dev.neta.coordinator.rules.RuleConvergenceService.RuleControl;
import dev.neta.coordinator.security.PeerCertificateService;
import dev.neta.coordinator.upgrade.AgentUpgradeInstruction;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class CoordinatorController {
    private final EnrollmentService enrollment;
    private final MessageIngestService ingest;
    private final PeerCertificateService certificates;
    private final RuleConvergenceService ruleConvergence;

    public CoordinatorController(EnrollmentService enrollment, MessageIngestService ingest,
                                 PeerCertificateService certificates,
                                 RuleConvergenceService ruleConvergence) {
        this.enrollment = enrollment;
        this.ingest = ingest;
        this.certificates = certificates;
        this.ruleConvergence = ruleConvergence;
    }

    @PostMapping("/enrollment")
    @ResponseStatus(HttpStatus.CREATED)
    public EnrollmentResponse enroll(@RequestBody EnrollmentRequest request) { return enrollment.enroll(request); }

    @PostMapping("/messages")
    public MessageResponse message(@RequestBody MessageEnvelope envelope, HttpServletRequest request) {
        IngestResult result = ingest.ingest(envelope, certificates.peerCertificate(request).orElse(null));
        RuleControl rules = null;
        if (envelope.messageType() == MessageType.HEARTBEAT || envelope.messageType() == MessageType.AGENT_HELLO) {
            rules = ruleConvergence.controlForAgent(envelope.agentId());
        }
        return new MessageResponse("neta-agent/1", 1, "Ack", 1,
                result.messageId(), result.sequence(), result.idempotencyKey(),
                result.payloadHash(), result.status(), result.receivedAt(), result.upgrade(), rules);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record MessageResponse(String protocol, int schemaVersion, String messageType,
                                  int ackVersion, String messageId, long sequence,
                                  String idempotencyKey, String payloadHash,
                                  String status,
                                  @JsonFormat(shape = JsonFormat.Shape.STRING) Instant receivedAt,
                                  AgentUpgradeInstruction upgrade, RuleControl rules) {}
}
