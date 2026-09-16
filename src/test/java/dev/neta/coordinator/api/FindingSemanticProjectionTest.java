package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class FindingSemanticProjectionTest {
    @Test
    void preservesSemanticTypeSeparatelyFromRuleId() {
        var controller = new PortalReadApiController(
                mock(JdbcTemplate.class), new ObjectMapper());
        var changes = """
                ["Rule: BEH-001", "Finding type: PERIODIC_OUTBOUND_CONNECTION"]
                """;

        assertEquals("PERIODIC_OUTBOUND_CONNECTION",
                controller.findingAttribute(changes, "Finding type:", "BEH-001"));
    }
}
