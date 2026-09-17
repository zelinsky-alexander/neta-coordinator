package dev.neta.coordinator.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.finding.FindingQueryService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class FindingSurfaceConsistencyTest {
    @Test
    void structuredAndOperatorSurfacesRenderTheSameCoordinatorFinding() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        FindingQueryService queries = mock(FindingQueryService.class);
        FindingQueryService.Finding finding = new FindingQueryService.Finding(
                "F-1", "A-1", "endpoint-one", "proc.exe (42)", "PROCESS", "42", null,
                null, "PROC-002", "PROCESS_BEHAVIOR", "HIGH", "0.90", "BEHAVIORAL_PATTERN", null, null,
                3, "ACTIVE", "CURRENT_ACTIONABLE", Instant.parse("2026-09-17T10:00:00Z"),
                Instant.parse("2026-09-17T11:00:00Z"), "INC-1", null, null, null, null);
        when(queries.search(any(), any())).thenReturn(
                new FindingQueryService.Page(List.of(finding), 1, false));

        PortalReadApiController structured = new PortalReadApiController(jdbc, new ObjectMapper(), queries);
        PortalReadApiController.FindingPage page = structured.findings(
                50, null, null, null, null, null, null, null, null, null, null, null);
        String operator = new FindingInvestigationController(jdbc, new ObjectMapper(), queries).search(
                null, null, null, null, null, null, "last_seen", "desc", 10, 0);

        assertEquals(List.of("F-1"), page.items().stream().map(PortalReadApiController.FindingItem::id).toList());
        assertEquals("HIGH", page.items().getFirst().severity());
        assertEquals("ACTIVE", page.items().getFirst().status());
        assertEquals(Instant.parse("2026-09-17T11:00:00Z"), page.items().getFirst().lastSeen());
        assertEquals("INC-1", page.items().getFirst().incidentId());
        assertTrue(operator.contains("F-1"));
        assertTrue(operator.contains("HIGH"));
        assertTrue(operator.contains("ACTIVE"));
        assertTrue(operator.contains("INC-1"));
        assertTrue(operator.contains("2026-09-17T11:00:00Z"));
        assertTrue(operator.contains("    3"));
    }

    @Test
    void operatorSummaryUsesCoordinatorAggregateWithoutRecounting() {
        FindingQueryService queries = mock(FindingQueryService.class);
        FindingQueryService.Summary summary = new FindingQueryService.Summary(
                2865, 123, 314, 187, Instant.parse("2026-09-13T12:00:00Z"), 0, 3, 120, 0);
        when(queries.summary()).thenReturn(summary);
        assertEquals(summary, new PortalReadApiController(mock(JdbcTemplate.class),
                new ObjectMapper(), queries).findingSummary());
        String output = new FindingInvestigationController(mock(JdbcTemplate.class),
                new ObjectMapper(), queries).summary();
        assertTrue(output.contains("Retained"));
        assertTrue(output.contains("2865"));
        assertTrue(output.contains("Current actionable"));
        assertTrue(output.contains("123"));
        assertTrue(output.contains("Recent candidates"));
        assertTrue(output.contains("187"));
    }
}
