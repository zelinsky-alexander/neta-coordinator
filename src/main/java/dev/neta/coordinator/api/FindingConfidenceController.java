package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigDecimal;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/findings")
public class FindingConfidenceController {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public FindingConfidenceController(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @GetMapping("/{findingId}/confidence")
    public ConfidenceView confidence(@PathVariable String findingId) {
        List<ConfidenceView> rows = jdbc.query("""
                SELECT finding_id,rule_id,base_severity,severity,risk_score,status,
                       confidence_score,confidence_level,corroboration_count,
                       corroborated_by::text,confidence_reasons::text
                  FROM findings WHERE finding_id=?
                """, (rs,n) -> new ConfidenceView(
                rs.getString("finding_id"),
                rs.getString("rule_id"),
                rs.getString("base_severity"),
                rs.getString("severity"),
                rs.getObject("risk_score", Integer.class),
                rs.getString("status"),
                confidence(rs.getBigDecimal("confidence_score")),
                rs.getString("confidence_level"),
                rs.getInt("corroboration_count"),
                json(rs.getString("corroborated_by")),
                json(rs.getString("confidence_reasons"))), findingId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"finding not found");
        return rows.getFirst();
    }

    private static Double confidence(BigDecimal value) {
        return value == null ? null : value.doubleValue();
    }

    private JsonNode json(String value) {
        try { return mapper.readTree(value == null || value.isBlank() ? "[]" : value); }
        catch (Exception e) { throw new IllegalStateException("stored EDR-Q1 confidence provenance is invalid JSON", e); }
    }

    public record ConfidenceView(String findingId,String ruleId,String baseSeverity,String severity,
                                 Integer riskScore,String status,Double score,String level,
                                 int corroborationCount,JsonNode corroboratedBy,JsonNode reasons) {}
}
