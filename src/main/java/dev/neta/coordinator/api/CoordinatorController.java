package dev.neta.coordinator.api;

import dev.neta.coordinator.enrollment.EnrollmentService;
import dev.neta.coordinator.enrollment.EnrollmentService.EnrollmentRequest;
import dev.neta.coordinator.enrollment.EnrollmentService.EnrollmentResponse;
import dev.neta.coordinator.ingest.MessageIngestService;
import dev.neta.coordinator.ingest.MessageIngestService.IngestResult;
import dev.neta.coordinator.protocol.MessageEnvelope;
import dev.neta.coordinator.security.PeerCertificateService;
import jakarta.servlet.http.HttpServletRequest;
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

    public CoordinatorController(EnrollmentService enrollment, MessageIngestService ingest, PeerCertificateService certificates) {
        this.enrollment = enrollment; this.ingest = ingest; this.certificates = certificates;
    }

    @PostMapping("/enrollment")
    @ResponseStatus(HttpStatus.CREATED)
    public EnrollmentResponse enroll(@RequestBody EnrollmentRequest request) { return enrollment.enroll(request); }

    @PostMapping("/messages")
    public IngestResult message(@RequestBody MessageEnvelope envelope, HttpServletRequest request) {
        return ingest.ingest(envelope, certificates.sha256Fingerprint(request).orElse(null));
    }
}
