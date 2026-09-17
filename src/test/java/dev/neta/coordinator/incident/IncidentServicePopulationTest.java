package dev.neta.coordinator.incident;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class IncidentServicePopulationTest {
    @Test
    void currentActionableDominatesIncidentPopulation() {
        assertEquals(IncidentService.CURRENT_ACTIONABLE,
                IncidentService.derivePopulation(1, 2));
        assertEquals("OPEN",
                IncidentService.lifecycleStatus(IncidentService.CURRENT_ACTIONABLE));
    }

    @Test
    void activeWithoutCurrentEvidenceBecomesHistorical() {
        assertEquals(IncidentService.ACTIVE_HISTORICAL,
                IncidentService.derivePopulation(0, 3));
        assertEquals("CLOSED",
                IncidentService.lifecycleStatus(IncidentService.ACTIVE_HISTORICAL));
    }

    @Test
    void candidateOnlyIncidentIsNotOpen() {
        assertEquals(IncidentService.CANDIDATE_ONLY,
                IncidentService.derivePopulation(0, 0));
        assertEquals("CLOSED",
                IncidentService.lifecycleStatus(IncidentService.CANDIDATE_ONLY));
    }

    @Test
    void onlyLiveFindingStatesParticipateInIncidents() {
        assertTrue(IncidentService.liveFindingStatus("ACTIVE"));
        assertTrue(IncidentService.liveFindingStatus("candidate"));
        assertFalse(IncidentService.liveFindingStatus("RESOLVED"));
        assertFalse(IncidentService.liveFindingStatus("SUPPRESSED"));
        assertFalse(IncidentService.liveFindingStatus(null));
    }

    @Test
    void populationAliasesAreNormalized() {
        assertEquals(IncidentService.CURRENT_ACTIONABLE,
                IncidentService.normalizePopulation("current"));
        assertEquals(IncidentService.ACTIVE_HISTORICAL,
                IncidentService.normalizePopulation("historical"));
        assertEquals(IncidentService.CANDIDATE_ONLY,
                IncidentService.normalizePopulation("candidate"));
        assertEquals(IncidentService.ALL,
                IncidentService.normalizePopulation("any"));
    }

    @Test
    void unknownPopulationIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> IncidentService.normalizePopulation("open-everything"));
    }
}
