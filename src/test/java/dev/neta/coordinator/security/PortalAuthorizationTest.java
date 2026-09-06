package dev.neta.coordinator.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class PortalAuthorizationTest {
    @Test
    void acceptsConfiguredPortalActorWithSufficientRole() {
        PortalAuthorization auth = new PortalAuthorization("secret-token");
        PortalAuthorization.Actor actor = auth.require("secret-token", "alex", "ADMIN", "neta-portal-prod",
                "req-1", "idem-1", PortalAuthorization.Role.OPERATOR);
        assertEquals("alex", actor.user());
        assertEquals(PortalAuthorization.Role.ADMIN, actor.role());
    }

    @Test
    void rejectsInsufficientRole() {
        PortalAuthorization auth = new PortalAuthorization("secret-token");
        assertThrows(ResponseStatusException.class, () -> auth.require("secret-token", "alice", "VIEWER",
                "neta-portal-prod", "req-1", null, PortalAuthorization.Role.OPERATOR));
    }

    @Test
    void rejectsInvalidServiceToken() {
        PortalAuthorization auth = new PortalAuthorization("secret-token");
        assertThrows(ResponseStatusException.class, () -> auth.require("wrong", "alex", "ADMIN",
                "neta-portal-prod", "req-1", null, PortalAuthorization.Role.VIEWER));
    }
}
