package dev.neta.coordinator.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public class PortalAuthorization {
    public enum Role { VIEWER, OPERATOR, ADMIN }
    public record Actor(String user, Role role, String service, String requestId, String idempotencyKey) {}

    private final String serviceToken;

    public PortalAuthorization(@Value("${NETA_PORTAL_SERVICE_TOKEN:}") String serviceToken) {
        this.serviceToken = serviceToken == null ? "" : serviceToken;
    }

    public Actor require(String suppliedToken, String actor, String role, String service,
                         String requestId, String idempotencyKey, Role required) {
        if (serviceToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "portal authorization is disabled; configure NETA_PORTAL_SERVICE_TOKEN");
        }
        byte[] expected = serviceToken.getBytes(StandardCharsets.UTF_8);
        byte[] supplied = (suppliedToken == null ? "" : suppliedToken).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, supplied)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid portal service token");
        }
        String user = clean(actor, "portal actor", 128);
        String serviceName = clean(service, "portal service", 128);
        Role parsed;
        try { parsed = Role.valueOf(clean(role, "portal actor role", 32).toUpperCase(Locale.ROOT)); }
        catch (IllegalArgumentException e) { throw new ResponseStatusException(HttpStatus.FORBIDDEN, "invalid portal actor role"); }
        if (parsed.ordinal() < required.ordinal()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "portal actor lacks required role " + required);
        }
        return new Actor(user, parsed, serviceName, optional(requestId, 128), optional(idempotencyKey, 128));
    }

    public Actor requireRead(String suppliedToken, String actor, String role, String service, String requestId) {
        return require(suppliedToken, actor, role, service, requestId, null, Role.VIEWER);
    }

    private static String clean(String value, String label, int max) {
        if (value == null || value.isBlank() || value.length() > max || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, label + " is required and must be <= " + max + " characters");
        }
        return value.trim();
    }

    private static String optional(String value, int max) {
        if (value == null || value.isBlank()) return null;
        if (value.length() > max || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "request context header is too long or malformed");
        }
        return value.trim();
    }
}
