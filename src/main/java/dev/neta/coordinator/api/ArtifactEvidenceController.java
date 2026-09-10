package dev.neta.coordinator.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/artifacts")
public class ArtifactEvidenceController {
    private final JdbcTemplate jdbc;
    private final ObjectMapper json;

    public ArtifactEvidenceController(JdbcTemplate jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    @GetMapping("/evidence")
    public ArtifactEvidencePage evidence(
            @RequestParam(value = "agentId", required = false) String agentId,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "limit", defaultValue = "100") int requestedLimit) {
        int limit = Math.max(1, Math.min(requestedLimit, 500));
        String normalizedAgent = agentId == null || agentId.isBlank() ? null : agentId.trim();
        String normalizedState = state == null || state.isBlank() ? null : state.trim().toUpperCase();

        String sql = """
                SELECT e.evidence_id,e.agent_id,coalesce(a.display_name,a.agent_id) endpoint_name,
                       e.message_id,e.artifact_sha256,e.artifact_path,e.artifact_size,
                       e.provider_name,e.provider_version,e.ruleset_id,e.ruleset_sha256,
                       e.scan_state,e.detail,e.matches::text,e.observed_at,e.first_seen,e.last_seen,
                       e.observation_count
                  FROM artifact_evidence e
                  JOIN agents a ON a.agent_id=e.agent_id
                 WHERE (CAST(? AS text) IS NULL OR e.agent_id=CAST(? AS text))
                   AND (CAST(? AS text) IS NULL OR upper(e.scan_state)=CAST(? AS text))
                 ORDER BY e.last_seen DESC,e.evidence_id DESC
                 LIMIT ?
                """;
        List<ArtifactEvidenceItem> items = jdbc.query(sql,
                (rs, rowNum) -> item(rs),
                normalizedAgent, normalizedAgent, normalizedState, normalizedState, limit);
        return new ArtifactEvidencePage(items, items.size(), limit);
    }

    private ArtifactEvidenceItem item(ResultSet rs) throws SQLException {
        Long size = rs.getObject("artifact_size", Long.class);
        return new ArtifactEvidenceItem(
                rs.getLong("evidence_id"),
                rs.getString("agent_id"),
                rs.getString("endpoint_name"),
                rs.getString("message_id"),
                rs.getString("artifact_sha256"),
                rs.getString("artifact_path"),
                size,
                rs.getString("provider_name"),
                rs.getString("provider_version"),
                rs.getString("ruleset_id"),
                rs.getString("ruleset_sha256"),
                rs.getString("scan_state"),
                rs.getString("detail"),
                parse(rs.getString("matches")),
                instant(rs, "observed_at"),
                instant(rs, "first_seen"),
                instant(rs, "last_seen"),
                rs.getLong("observation_count"));
    }

    private JsonNode parse(String value) {
        try { return json.readTree(value == null || value.isBlank() ? "[]" : value); }
        catch (JsonProcessingException e) { throw new IllegalStateException("stored artifact matches are invalid JSON", e); }
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        var value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    public record ArtifactEvidencePage(List<ArtifactEvidenceItem> items, int count, int limit) {}
    public record ArtifactEvidenceItem(
            long evidenceId,
            String agentId,
            String endpointName,
            String messageId,
            String artifactSha256,
            String artifactPath,
            Long artifactSize,
            String providerName,
            String providerVersion,
            String rulesetId,
            String rulesetSha256,
            String scanState,
            String detail,
            JsonNode matches,
            Instant observedAt,
            Instant firstSeen,
            Instant lastSeen,
            long observationCount) {}
}
