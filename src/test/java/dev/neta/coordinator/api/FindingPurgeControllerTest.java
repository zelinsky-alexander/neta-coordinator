package dev.neta.coordinator.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.finding.FindingQueryService;
import dev.neta.coordinator.incident.IncidentService;
import dev.neta.coordinator.security.PortalAuthorization;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.server.ResponseStatusException;

class FindingPurgeControllerTest {
    @Test
    void purgeRejectsNonAdminPortalActor() {
        FindingBulkController controller = controller(mock(JdbcTemplate.class), mock(IncidentService.class));
        assertThrows(ResponseStatusException.class, () -> controller.purgeOne(
                "admin-secret", "portal-secret", "alice", "OPERATOR", "portal", "req-1", "idem-1",
                "F-1", "cleanup", true));
    }

    @Test
    void purgeRequiresExplicitConfirmation() {
        FindingBulkController controller = controller(mock(JdbcTemplate.class), mock(IncidentService.class));
        assertThrows(ResponseStatusException.class, () -> controller.purgeOne(
                "admin-secret", "portal-secret", "alex", "ADMIN", "portal", "req-1", "idem-1",
                "F-1", "cleanup", false));
    }

    @Test
    void purgeCleansRelationshipsAndKeepsAudit() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        IncidentService incidents = mock(IncidentService.class);
        when(jdbc.query(startsWith("SELECT COALESCE"), any(RowMapper.class), eq("idem-1")))
                .thenReturn(List.of());
        when(jdbc.update(eq("DELETE FROM findings WHERE finding_id=?"), eq("F-1"))).thenReturn(1);

        FindingBulkController.BulkResult result = controller(jdbc, incidents).purgeOne(
                "admin-secret", "portal-secret", "alex", "ADMIN", "portal", "req-1", "idem-1",
                "F-1", "retention cleanup", true);

        assertEquals(1, result.affected());
        verify(jdbc).update(eq("UPDATE corroboration_requests SET finding_id=NULL WHERE finding_id=?"), eq("F-1"));
        verify(jdbc).update(eq("DELETE FROM incident_findings WHERE finding_id=?"), eq("F-1"));
        verify(jdbc).update(contains("DELETE FROM incidents"));
        verify(jdbc).update(contains("INSERT INTO audit_events"), eq("FINDING_PURGED"), isNull(),
                contains("\"actor\":\"alex\""));
        verify(incidents).syncAll();
    }

    private static FindingBulkController controller(JdbcTemplate jdbc, IncidentService incidents) {
        return new FindingBulkController(jdbc, new ObjectMapper(), incidents,
                new PortalAuthorization("portal-secret"), mock(FindingQueryService.class), "admin-secret");
    }
}
