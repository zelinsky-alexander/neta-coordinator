package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.JsonNode;
import dev.neta.coordinator.rules.ManagedRule;
import dev.neta.coordinator.rules.RuleManagementService;
import dev.neta.coordinator.rules.RuleManagementService.PublishedRuleSet;
import dev.neta.coordinator.security.PeerCertificateService;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1")
public class RuleManagementController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";
    private final RuleManagementService rules;
    private final PeerCertificateService certificates;
    private final JdbcTemplate jdbc;
    private final String adminToken;

    public RuleManagementController(RuleManagementService rules,
                                    PeerCertificateService certificates,
                                    JdbcTemplate jdbc,
                                    @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.rules = rules;
        this.certificates = certificates;
        this.jdbc = jdbc;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @GetMapping("/rules")
    public RuleCatalogResponse listRules() {
        PublishedRuleSet active = activeOrNull();
        return new RuleCatalogResponse(rules.currentRules(), active == null ? null : summary(active));
    }

    @PostMapping("/operator/rules/custom")
    public ManagedRule createCustom(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                                    @RequestHeader(value = "X-NETA-Actor", required = false) String actor,
                                    @RequestBody CustomRuleRequest request) {
        requireAdmin(suppliedToken);
        try {
            return rules.createCustom(request.id(), request.engineRuleId(), request.name(), request.severity(),
                    request.enabled() == null || request.enabled(), request.parameters(), actor);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    @PutMapping("/operator/rules/{id}")
    public ManagedRule revise(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                              @RequestHeader(value = "X-NETA-Actor", required = false) String actor,
                              @PathVariable String id,
                              @RequestBody RuleRevisionRequest request) {
        requireAdmin(suppliedToken);
        try {
            return rules.revise(id, request.name(), request.severity(), request.enabled(), request.parameters(), actor);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    @PostMapping("/operator/rule-sets/publish")
    public PublishedRuleSet publish(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
                                    @RequestHeader(value = "X-NETA-Actor", required = false) String actor) {
        requireAdmin(suppliedToken);
        return rules.publish(actor);
    }

    @GetMapping("/rule-sets/active")
    public PublishedRuleSet active() {
        try { return rules.active(); }
        catch (IllegalStateException e) { throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e); }
    }

    @GetMapping(value = "/agent/rules/bundle", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> bundleForAgent(HttpServletRequest request) {
        authenticatedAgent(request);
        PublishedRuleSet active;
        try { active = rules.active(); }
        catch (IllegalStateException e) { throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e); }
        return ResponseEntity.ok()
                .header("X-NETA-Rule-Revision", Long.toString(active.revision()))
                .header("X-NETA-Rule-Version", active.version())
                .header("X-NETA-Rule-SHA256", active.sha256())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.APPLICATION_JSON)
                .body(active.bundleText());
    }

    @GetMapping("/agent/rules/current")
    public AgentRuleBundle currentForAgent(HttpServletRequest request) {
        String agentId = authenticatedAgent(request);
        PublishedRuleSet active;
        try { active = rules.active(); }
        catch (IllegalStateException e) { throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e); }
        return new AgentRuleBundle(agentId, active.revision(), active.version(), active.sha256(), active.bundle());
    }

    @PostMapping("/agent/rules/ack")
    public AckResponse acknowledge(HttpServletRequest servletRequest, @RequestBody RuleAck request) {
        String agentId = authenticatedAgent(servletRequest);
        if (request.sha256() == null || request.sha256().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sha256 is required");
        }
        String state = request.status() == null || request.status().isBlank() ? "ACTIVE" : request.status().trim().toUpperCase();
        rules.acknowledge(agentId, request.revision(), request.sha256(), state, request.error());
        return new AckResponse(true, agentId, request.revision(), request.sha256(), state);
    }

    private String authenticatedAgent(HttpServletRequest request) {
        String fingerprint = certificates.sha256Fingerprint(request)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "agent mTLS certificate is required"));
        List<String> agents = jdbc.query("""
                SELECT agent_id FROM agents
                WHERE certificate_sha256=? AND status='ACTIVE'
                LIMIT 2
                """, (rs, n) -> rs.getString(1), fingerprint);
        if (agents.size() != 1) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "agent certificate is not bound to one active endpoint");
        return agents.getFirst();
    }

    private PublishedRuleSet activeOrNull() {
        try { return rules.active(); }
        catch (IllegalStateException ignored) { return null; }
    }

    private void requireAdmin(String suppliedToken) {
        if (adminToken.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "rule administration is disabled; configure NETA_OPERATOR_ADMIN_TOKEN");
        byte[] expected = adminToken.getBytes(StandardCharsets.UTF_8);
        byte[] supplied = (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, supplied)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
    }

    private static RuleSetSummary summary(PublishedRuleSet set) {
        return new RuleSetSummary(set.revision(), set.version(), set.sha256(), set.publishedAt());
    }

    public record RuleCatalogResponse(List<ManagedRule> items, RuleSetSummary activeRuleSet) {}
    public record RuleSetSummary(long revision, String version, String sha256, java.time.Instant publishedAt) {}
    public record CustomRuleRequest(String id, String engineRuleId, String name, String severity, Boolean enabled, JsonNode parameters) {}
    public record RuleRevisionRequest(String name, String severity, Boolean enabled, JsonNode parameters) {}
    public record AgentRuleBundle(String agentId, long revision, String version, String sha256, JsonNode bundle) {}
    public record RuleAck(long revision, String sha256, String status, String error) {}
    public record AckResponse(boolean accepted, String agentId, long revision, String sha256, String status) {}
}
