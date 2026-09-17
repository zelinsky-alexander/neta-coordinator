package dev.neta.coordinator.finding;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class FindingQueryServiceTest {
    private static final Instant NOW = Instant.parse("2026-09-17T12:00:00Z");
    private final FindingQueryService service = new FindingQueryService(
            org.mockito.Mockito.mock(JdbcTemplate.class), new ObjectMapper(), Duration.ofHours(24),
            Duration.ofHours(1), Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void defaultPopulationUsesCurrentActionableBoundary() {
        FindingQueryService.Selection selection = service.selection(FindingQueryService.Filter.defaults());
        assertTrue(selection.where().contains("status,''))='ACTIVE'"));
        assertTrue(selection.where().contains("last_seen>=?"));
        assertEquals(Timestamp.from(NOW.minus(Duration.ofHours(24))), selection.args().getFirst());
    }

    @Test
    void lifecyclePopulationsShareExactBoundaries() {
        FindingQueryService.Selection historical = service.selection(filter("ACTIVE_HISTORICAL"));
        FindingQueryService.Selection recentCandidates = service.selection(filter("RECENT_CANDIDATES"));
        FindingQueryService.Selection active = service.selection(filter("ACTIVE"));
        FindingQueryService.Selection all = service.selection(filter("ALL"));

        assertTrue(historical.where().contains("last_seen<?"));
        assertEquals(Timestamp.from(NOW.minus(Duration.ofHours(24))), historical.args().getFirst());
        assertTrue(recentCandidates.where().contains("status,''))='CANDIDATE'"));
        assertEquals(Timestamp.from(NOW.minus(Duration.ofHours(1))), recentCandidates.args().getFirst());
        assertTrue(active.where().contains("status,''))=?"));
        assertEquals("ACTIVE", active.args().getFirst());
        assertFalse(all.where().contains("f.status"));
    }

    @Test
    void explicitAgeAndCandidateFiltersCompose() {
        FindingQueryService.Filter filter = new FindingQueryService.Filter(null, null, null,
                "CANDIDATE", null, "LOW", null, null, null, 3600L);
        FindingQueryService.Selection selection = service.selection(filter);
        assertTrue(selection.where().contains("f.status"));
        assertTrue(selection.where().contains("f.severity"));
        assertTrue(selection.where().contains("f.last_seen>=?"));
        assertEquals("CANDIDATE", selection.args().get(1));
        assertEquals(Timestamp.from(NOW.minusSeconds(3600)), selection.args().get(2));
    }

    private static FindingQueryService.Filter filter(String population) {
        return new FindingQueryService.Filter(null, null, null, population, null,
                null, null, null, null, null);
    }
}
