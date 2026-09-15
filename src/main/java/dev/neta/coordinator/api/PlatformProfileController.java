package dev.neta.coordinator.api;

import dev.neta.coordinator.rules.PlatformProfileService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Operator API for deterministic platform profiles and their trusted rule-policy deltas. */
@RestController
@RequestMapping("/api/v1/operator/platform-profiles")
public class PlatformProfileController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";
    private final PlatformProfileService profiles;
    private final String adminToken;

    public PlatformProfileController(PlatformProfileService profiles,
                                     @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.profiles = profiles;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @GetMapping
    public Overview overview(@RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken) {
        requireAdmin(suppliedToken);
        return new Overview(profiles.definitions(), profiles.rulePatches(), profiles.assignments());
    }

    @GetMapping("/{agentId}")
    public PlatformProfileService.EffectiveProfile effective(
            @RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
            @PathVariable String agentId) {
        requireAdmin(suppliedToken);
        try { return profiles.effective(agentId); }
        catch (IllegalArgumentException | IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    @PostMapping("/{agentId}")
    public PlatformProfileService.EndpointProfile assign(
            @RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
            @RequestHeader(value = "X-NETA-Actor", required = false) String actor,
            @PathVariable String agentId,
            @RequestBody AssignRequest request) {
        requireAdmin(suppliedToken);
        try { return profiles.assign(agentId, request == null ? null : request.profileId(), actor); }
        catch (IllegalArgumentException | IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    @PutMapping("/definitions/{profileId}/rules/{ruleId}")
    public PlatformProfileService.ProfileRulePatch updateRulePatch(
            @RequestHeader(value = ADMIN_HEADER, required = false) String suppliedToken,
            @RequestHeader(value = "X-NETA-Actor", required = false) String actor,
            @PathVariable String profileId,
            @PathVariable String ruleId,
            @RequestBody RulePatchRequest request) {
        requireAdmin(suppliedToken);
        try {
            Map<String, ?> parameters = request == null || request.parametersPatch() == null ? Map.of() : request.parametersPatch();
            Map<String, ?> exclusions = request == null || request.exclusionsPatch() == null ? Map.of() : request.exclusionsPatch();
            return profiles.updateRulePatch(profileId, ruleId, parameters, exclusions, actor);
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    private void requireAdmin(String suppliedToken) {
        if (adminToken.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "platform profile administration is disabled; configure NETA_OPERATOR_ADMIN_TOKEN");
        byte[] expected = adminToken.getBytes(StandardCharsets.UTF_8);
        byte[] supplied = (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, supplied))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
    }

    public record AssignRequest(String profileId) {}
    public record RulePatchRequest(Map<String, Object> parametersPatch, Map<String, Object> exclusionsPatch) {}
    public record Overview(List<PlatformProfileService.ProfileDefinition> profiles,
                           List<PlatformProfileService.ProfileRulePatch> rulePatches,
                           List<PlatformProfileService.EndpointProfile> endpoints) {}
}
