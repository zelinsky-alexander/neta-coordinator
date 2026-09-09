package dev.neta.coordinator.rules;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RuleManagementService {
    private static final Set<String> CUSTOM_ENGINES = Set.of(
            "NETA-PROC-001", "NETA-PROC-002", "NETA-PROC-003", "NETA-PROC-004", "NETA-PROC-005",
            "NETA-BEH-001", "NETA-NET-001", "NETA-NET-002", "NETA-NET-003", "NETA-NET-004",
            "NETA-DNS-001", "NETA-DNS-002", "NETA-DNS-003",
            "NETA-TLS-001", "NETA-TLS-002", "NETA-ROUTE-001");

    private final JdbcTemplate jdbc;
    private final ObjectMapper json;

    public RuleManagementService(JdbcTemplate jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public List<ManagedRule> currentRules() {
        return jdbc.query("""
                SELECT DISTINCT ON (rule_id)
                       rule_id, revision, origin, engine_rule_id, name, category, severity, enabled,
                       parameters_json::text, created_by, created_at
                FROM rule_definitions
                ORDER BY rule_id, revision DESC
                """, (rs, n) -> new ManagedRule(
                rs.getString(1), rs.getLong(2), rs.getString(3), rs.getString(4), rs.getString(5),
                rs.getString(6), rs.getString(7), rs.getBoolean(8), parse(rs.getString(9)),
                rs.getString(10), instant(rs.getTimestamp(11))));
    }

    @Transactional
    public ManagedRule createCustom(String requestedId, String engineRuleId, String name, String severity,
                                    boolean enabled, JsonNode parameters, String actor) {
        String engine = required(engineRuleId, "engineRuleId").toUpperCase(Locale.ROOT);
        if (!CUSTOM_ENGINES.contains(engine)) {
            throw new IllegalArgumentException(
                    "custom rules require a multi-instance process, behavior, network, DNS, TLS, or route engine");
        }
        String id = requestedId == null || requestedId.isBlank()
                ? "CUS-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(Locale.ROOT)
                : requestedId.trim().toUpperCase(Locale.ROOT);
        if (!id.matches("CUS-[A-Z0-9._-]{3,60}"))
            throw new IllegalArgumentException("custom rule id must match CUS-[A-Z0-9._-]{3,60}");
        if (exists(id)) throw new IllegalArgumentException("rule already exists: " + id);
        String normalizedSeverity = severity == null ? "medium" : severity.trim().toLowerCase(Locale.ROOT);
        if (!Set.of("low", "medium", "high").contains(normalizedSeverity))
            throw new IllegalArgumentException("severity must be low, medium, or high");
        JsonNode params = parameters == null ? json.createObjectNode() : parameters;
        if (!params.isObject()) throw new IllegalArgumentException("parameters must be a JSON object");
        validateParametersAgainstEngine(engine, params);
        jdbc.update("""
                INSERT INTO rule_definitions(rule_id,revision,origin,engine_rule_id,name,category,severity,enabled,parameters_json,created_by)
                VALUES (?,1,'CUSTOM',?,?,?,?,?,?::jsonb,?)
                """, id, engine, required(name, "name"), engineCategory(engine), normalizedSeverity,
                enabled, write(params), actorValue(actor));
        return current(id);
    }

    @Transactional
    public ManagedRule revise(String id, String name, String severity, Boolean enabled, JsonNode parameters, String actor) {
        ManagedRule current = current(id);
        long revision = current.revision() + 1;
        String nextName = name == null || name.isBlank() ? current.name() : name.trim();
        String nextSeverity = severity == null || severity.isBlank() ? current.severity() : severity.trim().toLowerCase(Locale.ROOT);
        if (!Set.of("low", "medium", "high").contains(nextSeverity))
            throw new IllegalArgumentException("severity must be low, medium, or high");
        JsonNode nextParameters = parameters == null ? current.parameters() : parameters;
        if (!nextParameters.isObject()) throw new IllegalArgumentException("parameters must be a JSON object");
        validateParametersAgainstEngine(current.engineRuleId(), nextParameters);
        jdbc.update("""
                INSERT INTO rule_definitions(rule_id,revision,origin,engine_rule_id,name,category,severity,enabled,parameters_json,created_by)
                VALUES (?,?,?,?,?,?,?,?,?::jsonb,?)
                """, current.id(), revision, current.origin(), current.engineRuleId(), nextName, current.category(), nextSeverity,
                enabled == null ? current.enabled() : enabled, write(nextParameters), actorValue(actor));
        return current(id);
    }

    @Transactional
    public PublishedRuleSet publish(String actor) {
        List<ManagedRule> rules = currentRules();
        Long next = jdbc.queryForObject("SELECT COALESCE(MAX(revision),0)+1 FROM rule_sets", Long.class);
        long revision = next == null ? 1 : next;
        ObjectNode bundle = json.createObjectNode();
        bundle.put("schema_version", 2);
        bundle.put("id", "neta-production");
        bundle.put("revision", revision);
        bundle.put("version", "neta-rules/central-" + revision);
        ArrayNode array = bundle.putArray("rules");
        for (ManagedRule rule : rules) {
            ObjectNode item = array.addObject();
            item.put("id", rule.id());
            item.put("engine_rule_id", rule.engineRuleId());
            item.put("name", rule.name());
            item.put("category", rule.category());
            item.put("severity", rule.severity());
            item.put("enabled", rule.enabled());
            item.set("parameters", rule.parameters());
        }
        String canonical = write(bundle);
        String hash = sha256(canonical);
        jdbc.update("UPDATE rule_sets SET status='SUPERSEDED' WHERE status='ACTIVE'");
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO rule_sets(rule_set_id,revision,version,status,bundle_json,bundle_text,sha256,created_by)
                VALUES (?,?,?,'ACTIVE',?::jsonb,?,?,?)
                """, id, revision, bundle.get("version").asText(), canonical, canonical, hash, actorValue(actor));
        jdbc.update("""
                INSERT INTO agent_rule_state(agent_id,desired_revision,desired_sha256,status,updated_at)
                SELECT agent_id,?,?,CASE WHEN ?=COALESCE((SELECT active_sha256 FROM agent_rule_state ars WHERE ars.agent_id=agents.agent_id),'') THEN 'ACTIVE' ELSE 'STALE' END,now()
                FROM agents
                ON CONFLICT(agent_id) DO UPDATE SET desired_revision=excluded.desired_revision,
                    desired_sha256=excluded.desired_sha256,
                    status=CASE WHEN agent_rule_state.active_sha256=excluded.desired_sha256 THEN 'ACTIVE' ELSE 'STALE' END,
                    updated_at=now()
                """, revision, hash, hash);
        return new PublishedRuleSet(id, revision, bundle.get("version").asText(), hash, bundle, canonical, Instant.now());
    }

    public PublishedRuleSet active() {
        List<PublishedRuleSet> rows = jdbc.query("""
                SELECT rule_set_id,revision,version,sha256,bundle_json::text,bundle_text,published_at
                FROM rule_sets WHERE status='ACTIVE' ORDER BY revision DESC LIMIT 1
                """, (rs, n) -> new PublishedRuleSet(UUID.fromString(rs.getString(1)), rs.getLong(2), rs.getString(3),
                rs.getString(4), parse(rs.getString(5)), rs.getString(6), instant(rs.getTimestamp(7))));
        if (rows.isEmpty()) throw new IllegalStateException("no active rule set has been published");
        return rows.getFirst();
    }

    @Transactional
    public void acknowledge(String agentId, long revision, String sha256, String status, String error) {
        jdbc.update("""
                INSERT INTO agent_rule_state(agent_id,active_revision,active_sha256,status,last_error,updated_at)
                VALUES (?,?,?,?,?,now())
                ON CONFLICT(agent_id) DO UPDATE SET active_revision=excluded.active_revision,
                    active_sha256=excluded.active_sha256,status=excluded.status,last_error=excluded.last_error,updated_at=now()
                """, agentId, revision, sha256, status, error);
    }

    private String engineCategory(String engineRuleId) {
        List<String> categories = jdbc.query("""
                SELECT category FROM rule_definitions
                WHERE rule_id=? AND origin='DEFAULT' ORDER BY revision DESC LIMIT 1
                """, (rs, n) -> rs.getString(1), engineRuleId);
        if (categories.isEmpty()) throw new IllegalArgumentException("unknown engine rule: " + engineRuleId);
        return categories.getFirst();
    }

    private void validateParametersAgainstEngine(String engineRuleId, JsonNode parameters) {
        List<String> defaults = jdbc.query("""
                SELECT parameters_json::text FROM rule_definitions
                WHERE rule_id=? AND origin='DEFAULT' ORDER BY revision DESC LIMIT 1
                """, (rs, n) -> rs.getString(1), engineRuleId);
        if (defaults.isEmpty()) throw new IllegalArgumentException("unknown engine rule: " + engineRuleId);
        JsonNode schema = parse(defaults.getFirst());
        java.util.Iterator<String> expected = schema.fieldNames();
        Set<String> expectedNames = new java.util.HashSet<>();
        expected.forEachRemaining(expectedNames::add);
        Set<String> suppliedNames = new java.util.HashSet<>();
        parameters.fieldNames().forEachRemaining(suppliedNames::add);
        if (!expectedNames.equals(suppliedNames)) {
            throw new IllegalArgumentException("parameters for " + engineRuleId + " must contain exactly: " + expectedNames);
        }
        for (String field : expectedNames) {
            JsonNode expectedValue = schema.get(field);
            JsonNode supplied = parameters.get(field);
            boolean compatible = (expectedValue.isNumber() && supplied.isNumber())
                    || (expectedValue.isBoolean() && supplied.isBoolean())
                    || (expectedValue.isTextual() && supplied.isTextual())
                    || (expectedValue.isArray() && supplied.isArray());
            if (!compatible) throw new IllegalArgumentException("parameter " + field + " has the wrong JSON type");
            if (expectedValue.isArray()) {
                for (JsonNode item : supplied) {
                    if (!item.isTextual()) throw new IllegalArgumentException("array parameter " + field + " must contain strings");
                }
            }
        }
    }

    private ManagedRule current(String id) {
        List<ManagedRule> rows = jdbc.query("""
                SELECT rule_id,revision,origin,engine_rule_id,name,category,severity,enabled,parameters_json::text,created_by,created_at
                FROM rule_definitions WHERE rule_id=? ORDER BY revision DESC LIMIT 1
                """, (rs, n) -> new ManagedRule(rs.getString(1), rs.getLong(2), rs.getString(3), rs.getString(4),
                rs.getString(5), rs.getString(6), rs.getString(7), rs.getBoolean(8), parse(rs.getString(9)),
                rs.getString(10), instant(rs.getTimestamp(11))), id);
        if (rows.isEmpty()) throw new IllegalArgumentException("rule not found: " + id);
        return rows.getFirst();
    }

    private boolean exists(String id) {
        Integer count = jdbc.queryForObject("SELECT count(*) FROM rule_definitions WHERE rule_id=?", Integer.class, id);
        return count != null && count > 0;
    }

    private JsonNode parse(String value) {
        try { return json.readTree(value); }
        catch (JsonProcessingException e) { throw new IllegalStateException("invalid rule JSON in database", e); }
    }
    private String write(JsonNode value) {
        try { return json.writeValueAsString(value); }
        catch (JsonProcessingException e) { throw new IllegalStateException("cannot serialize rule JSON", e); }
    }
    private static String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }
    private static String required(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return value.trim();
    }
    private static String actorValue(String actor) { return actor == null || actor.isBlank() ? "operator" : actor.trim(); }
    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }

    public record PublishedRuleSet(UUID id, long revision, String version, String sha256,
                                   JsonNode bundle, String bundleText, Instant publishedAt) {}
}
