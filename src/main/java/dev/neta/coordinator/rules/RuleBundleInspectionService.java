package dev.neta.coordinator.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RuleBundleInspectionService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    private final RuleManagementService rules;

    public RuleBundleInspectionService(JdbcTemplate jdbc, ObjectMapper json, RuleManagementService rules) {
        this.jdbc = jdbc;
        this.json = json;
        this.rules = rules;
    }

    public BundleView base(long revision) {
        List<BundleView> rows = jdbc.query("""
                SELECT revision,version,sha256,bundle_json::text,published_at
                FROM rule_sets WHERE revision=? LIMIT 1
                """, (rs, n) -> new BundleView("BASE", null, null, rs.getLong(1), rs.getString(2),
                rs.getString(3), parse(rs.getString(4)), List.of(), instant(rs.getTimestamp(5))), revision);
        if (rows.isEmpty()) throw new IllegalArgumentException("published base rule revision not found: " + revision);
        return rows.getFirst();
    }

    @Transactional
    public BundleView desired(String agentId) {
        String endpoint = endpointName(agentId);
        RuleManagementService.EffectiveRuleSet effective = rules.effectiveForAgent(agentId);
        saveSnapshot(effective);
        return new BundleView("EFFECTIVE_DESIRED", agentId, endpoint, effective.revision(), effective.version(),
                effective.sha256(), effective.bundle(), effective.appliedOverrideIds(), Instant.now());
    }

    public BundleView active(String agentId) {
        String endpoint = endpointName(agentId);
        List<ActivePointer> state = jdbc.query("""
                SELECT active_revision,active_sha256 FROM agent_rule_state
                WHERE agent_id=? AND active_revision IS NOT NULL AND active_sha256 IS NOT NULL
                """, (rs, n) -> new ActivePointer(rs.getLong(1), rs.getString(2)), agentId);
        if (state.isEmpty()) throw new IllegalArgumentException("endpoint has no acknowledged active rule bundle: " + agentId);
        ActivePointer active = state.getFirst();

        List<BundleView> snapshots = jdbc.query("""
                SELECT revision,version,sha256,bundle_json::text,applied_override_ids::text,created_at
                FROM agent_rule_bundle_snapshots WHERE agent_id=? AND sha256=? LIMIT 1
                """, (rs, n) -> new BundleView("EFFECTIVE_ACTIVE", agentId, endpoint, rs.getLong(1), rs.getString(2),
                rs.getString(3), parse(rs.getString(4)), longList(rs.getString(5)), instant(rs.getTimestamp(6))),
                agentId, active.sha256());
        if (!snapshots.isEmpty()) return snapshots.getFirst();

        // Legacy agents often acknowledged the unmodified base bundle before effective snapshots existed.
        List<BundleView> baseMatch = jdbc.query("""
                SELECT revision,version,sha256,bundle_json::text,published_at
                FROM rule_sets WHERE revision=? AND lower(sha256)=lower(?) LIMIT 1
                """, (rs, n) -> new BundleView("EFFECTIVE_ACTIVE", agentId, endpoint, rs.getLong(1), rs.getString(2),
                rs.getString(3), parse(rs.getString(4)), List.of(), instant(rs.getTimestamp(5))),
                active.revision(), active.sha256());
        if (!baseMatch.isEmpty()) return baseMatch.getFirst();

        throw new IllegalStateException("exact legacy endpoint-effective bundle was not retained; refresh/converge the endpoint to snapshot it");
    }

    @Transactional
    public void snapshotDesiredForAgent(String agentId) {
        saveSnapshot(rules.effectiveForAgent(agentId));
    }

    private void saveSnapshot(RuleManagementService.EffectiveRuleSet effective) {
        try {
            String overrideJson = json.writeValueAsString(effective.appliedOverrideIds());
            jdbc.update("""
                    INSERT INTO agent_rule_bundle_snapshots(agent_id,revision,sha256,version,bundle_json,bundle_text,applied_override_ids)
                    VALUES (?,?,?,?,?::jsonb,?,?::jsonb)
                    ON CONFLICT(agent_id,sha256) DO NOTHING
                    """, effective.agentId(), effective.revision(), effective.sha256(), effective.version(),
                    json.writeValueAsString(effective.bundle()), effective.bundleText(), overrideJson);
        } catch (Exception e) {
            throw new IllegalStateException("cannot persist endpoint rule bundle snapshot", e);
        }
    }

    private String endpointName(String agentId) {
        List<String> rows = jdbc.query("SELECT display_name FROM agents WHERE agent_id=? LIMIT 1",
                (rs, n) -> rs.getString(1), agentId);
        if (rows.isEmpty()) throw new IllegalArgumentException("endpoint not found: " + agentId);
        return rows.getFirst();
    }

    private JsonNode parse(String text) {
        try { return json.readTree(text); }
        catch (Exception e) { throw new IllegalStateException("stored rule bundle is invalid JSON", e); }
    }

    private List<Long> longList(String text) {
        JsonNode node = parse(text);
        if (!node.isArray()) return List.of();
        java.util.ArrayList<Long> values = new java.util.ArrayList<>();
        node.forEach(item -> values.add(item.asLong()));
        return List.copyOf(values);
    }

    private static Instant instant(java.sql.Timestamp value) { return value == null ? null : value.toInstant(); }

    private record ActivePointer(long revision, String sha256) {}

    public record BundleView(String kind, String agentId, String endpointName, long revision, String version,
                             String sha256, JsonNode bundle, List<Long> appliedOverrideIds, Instant capturedAt) {}
}
