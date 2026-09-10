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
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
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
            "PROC-001", "PROC-002", "PROC-003", "PROC-004", "PROC-005",
            "BEH-001", "NET-001", "NET-002", "NET-003", "NET-004",
            "DNS-001", "DNS-002", "DNS-003",
            "TLS-001", "TLS-002", "ROUTE-001");
    private static final Set<String> EXCLUSION_FIELDS = Set.of(
            "process_names", "executable_paths", "process_path_prefixes", "parent_process_names", "users",
            "remote_hosts", "remote_ips", "remote_ports", "local_ports", "domains", "directions");
    private static final Set<String> DIRECTIONS = Set.of("inbound", "outbound", "unknown");

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
                       parameters_json::text, exclusions_json::text, created_by, created_at
                FROM rule_definitions
                ORDER BY rule_id, revision DESC
                """, (rs, n) -> new ManagedRule(
                rs.getString(1), rs.getLong(2), rs.getString(3), rs.getString(4), rs.getString(5),
                rs.getString(6), rs.getString(7), rs.getBoolean(8), parse(rs.getString(9)), parse(rs.getString(10)),
                rs.getString(11), instant(rs.getTimestamp(12))));
    }

    @Transactional
    public ManagedRule createCustom(String requestedId, String engineRuleId, String name, String severity,
                                    boolean enabled, JsonNode parameters, JsonNode exclude, String actor) {
        String engine = required(engineRuleId, "engineRuleId").toUpperCase(Locale.ROOT);
        if (!CUSTOM_ENGINES.contains(engine)) {
            throw new IllegalArgumentException(
                    "custom rules require a multi-instance process, behavior, network, DNS, TLS, or route engine");
        }
        String id = requestedId == null || requestedId.isBlank()
                ? "CST-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(Locale.ROOT)
                : requestedId.trim().toUpperCase(Locale.ROOT);
        if (!id.matches("CST-[A-Z0-9._-]{3,60}"))
            throw new IllegalArgumentException("custom rule id must match CST-[A-Z0-9._-]{3,60}");
        if (exists(id)) throw new IllegalArgumentException("rule already exists: " + id);
        String normalizedSeverity = severity == null ? "medium" : severity.trim().toLowerCase(Locale.ROOT);
        if (!Set.of("low", "medium", "high").contains(normalizedSeverity))
            throw new IllegalArgumentException("severity must be low, medium, or high");
        JsonNode params = parameters == null ? json.createObjectNode() : parameters;
        if (!params.isObject()) throw new IllegalArgumentException("parameters must be a JSON object");
        validateParametersAgainstEngine(engine, params);
        JsonNode exclusions = validateExclusions(exclude);
        jdbc.update("""
                INSERT INTO rule_definitions(rule_id,revision,origin,engine_rule_id,name,category,severity,enabled,
                                             parameters_json,exclusions_json,created_by)
                VALUES (?,1,'CUSTOM',?,?,?,?,?,?::jsonb,?::jsonb,?)
                """, id, engine, required(name, "name"), engineCategory(engine), normalizedSeverity,
                enabled, write(params), write(exclusions), actorValue(actor));
        return current(id);
    }

    @Transactional
    public ManagedRule revise(String id, String name, String severity, Boolean enabled, JsonNode parameters,
                              JsonNode exclude, String actor) {
        ManagedRule current = current(id);
        long revision = current.revision() + 1;
        String nextName = name == null || name.isBlank() ? current.name() : name.trim();
        String nextSeverity = severity == null || severity.isBlank() ? current.severity() : severity.trim().toLowerCase(Locale.ROOT);
        if (!Set.of("low", "medium", "high").contains(nextSeverity))
            throw new IllegalArgumentException("severity must be low, medium, or high");
        JsonNode nextParameters = parameters == null ? current.parameters() : parameters;
        if (!nextParameters.isObject()) throw new IllegalArgumentException("parameters must be a JSON object");
        validateParametersAgainstEngine(current.engineRuleId(), nextParameters);
        JsonNode nextExclusions = exclude == null ? current.exclude() : validateExclusions(exclude);
        jdbc.update("""
                INSERT INTO rule_definitions(rule_id,revision,origin,engine_rule_id,name,category,severity,enabled,
                                             parameters_json,exclusions_json,created_by)
                VALUES (?,?,?,?,?,?,?,?,?::jsonb,?::jsonb,?)
                """, current.id(), revision, current.origin(), current.engineRuleId(), nextName, current.category(), nextSeverity,
                enabled == null ? current.enabled() : enabled, write(nextParameters), write(nextExclusions), actorValue(actor));
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
            item.set("exclude", rule.exclude());
        }
        String canonical = write(bundle);
        String hash = sha256(canonical);
        jdbc.update("UPDATE rule_sets SET status='SUPERSEDED' WHERE status='ACTIVE'");
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO rule_sets(rule_set_id,revision,version,status,bundle_json,bundle_text,sha256,created_by)
                VALUES (?,?,?,'ACTIVE',?::jsonb,?,?,?)
                """, id, revision, bundle.get("version").asText(), canonical, canonical, hash, actorValue(actor));
        PublishedRuleSet published = new PublishedRuleSet(id, revision, bundle.get("version").asText(), hash,
                bundle, canonical, Instant.now());
        refreshDesiredStates();
        return published;
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

    public EffectiveRuleSet effectiveForAgent(String agentId) {
        PublishedRuleSet published = active();
        ObjectNode bundle = published.bundle().deepCopy();
        List<RuleOverride> approved = approvedEndpointOverrides(agentId);
        if (!approved.isEmpty()) {
            JsonNode ruleArray = bundle.get("rules");
            if (ruleArray == null || !ruleArray.isArray())
                throw new IllegalStateException("published rule bundle has no rules array");
            for (RuleOverride override : approved) applyOverride((ArrayNode) ruleArray, override);
        }
        String text = write(bundle);
        return new EffectiveRuleSet(agentId, published.revision(), published.version(), sha256(text), bundle, text,
                approved.stream().map(RuleOverride::overrideId).toList());
    }

    public List<RuleOverride> ruleOverrides() {
        return jdbc.query("""
                SELECT o.override_id,o.scope_type,o.scope_id,o.rule_id,o.enabled_override,
                       o.parameters_patch::text,o.exclusions_patch::text,o.status,o.source_feedback_id,o.reason,
                       o.created_by,o.created_at,o.approved_at,a.display_name
                FROM rule_overrides o
                LEFT JOIN agents a ON o.scope_type='ENDPOINT' AND a.agent_id=o.scope_id
                ORDER BY CASE o.status WHEN 'STAGED' THEN 0 WHEN 'APPROVED' THEN 1 ELSE 2 END,
                         o.created_at DESC,o.override_id DESC
                """, (rs, n) -> new RuleOverride(
                rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4),
                rs.getObject(5, Boolean.class), parse(rs.getString(6)), parse(rs.getString(7)), rs.getString(8),
                rs.getObject(9, Long.class), rs.getString(10), rs.getString(11), instant(rs.getTimestamp(12)),
                instant(rs.getTimestamp(13)), rs.getString(14)));
    }

    @Transactional
    public RuleOverride approveEndpointOverride(long overrideId, String actor) {
        List<RuleOverride> matches = ruleOverrides().stream().filter(o -> o.overrideId() == overrideId).toList();
        if (matches.isEmpty()) throw new IllegalArgumentException("rule override not found: " + overrideId);
        RuleOverride candidate = matches.getFirst();
        if (!"STAGED".equals(candidate.status()))
            throw new IllegalArgumentException("only STAGED overrides can be approved");
        if (!"ENDPOINT".equals(candidate.scopeType()))
            throw new IllegalArgumentException("RM3.3 approval currently supports ENDPOINT overrides only");
        if (candidate.scopeId() == null || candidate.scopeId().isBlank())
            throw new IllegalArgumentException("endpoint override has no endpoint identity");
        ensureAgentActive(candidate.scopeId());
        ensureRuleInActiveBundle(candidate.ruleId());
        validatePatch(candidate);

        jdbc.update("UPDATE rule_overrides SET status='APPROVED',approved_at=now() WHERE override_id=? AND status='STAGED'",
                overrideId);
        EffectiveRuleSet effective = effectiveForAgent(candidate.scopeId());
        upsertDesiredState(candidate.scopeId(), effective);
        auditOverride("RULE_OVERRIDE_APPROVED", candidate, actor, effective);
        return ruleOverrides().stream().filter(o -> o.overrideId() == overrideId).findFirst()
                .orElseThrow(() -> new IllegalStateException("approved override disappeared"));
    }

    @Transactional
    public RuleOverride retireEndpointOverride(long overrideId, String actor) {
        List<RuleOverride> matches = ruleOverrides().stream().filter(o -> o.overrideId() == overrideId).toList();
        if (matches.isEmpty()) throw new IllegalArgumentException("rule override not found: " + overrideId);
        RuleOverride candidate = matches.getFirst();
        if (!"ENDPOINT".equals(candidate.scopeType()))
            throw new IllegalArgumentException("RM3.3 retirement currently supports ENDPOINT overrides only");
        if (!"APPROVED".equals(candidate.status()))
            throw new IllegalArgumentException("only APPROVED overrides can be retired");
        jdbc.update("UPDATE rule_overrides SET status='RETIRED' WHERE override_id=? AND status='APPROVED'", overrideId);
        EffectiveRuleSet effective = effectiveForAgent(candidate.scopeId());
        upsertDesiredState(candidate.scopeId(), effective);
        auditOverride("RULE_OVERRIDE_RETIRED", candidate, actor, effective);
        return ruleOverrides().stream().filter(o -> o.overrideId() == overrideId).findFirst()
                .orElseThrow(() -> new IllegalStateException("retired override disappeared"));
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

    private List<RuleOverride> approvedEndpointOverrides(String agentId) {
        return ruleOverrides().stream()
                .filter(o -> "APPROVED".equals(o.status()) && "ENDPOINT".equals(o.scopeType()) && agentId.equals(o.scopeId()))
                .sorted(java.util.Comparator.comparingLong(RuleOverride::overrideId))
                .toList();
    }

    private void applyOverride(ArrayNode rulesArray, RuleOverride override) {
        ObjectNode rule = null;
        for (JsonNode item : rulesArray) {
            if (item.isObject() && override.ruleId().equals(item.path("id").asText())) {
                rule = (ObjectNode) item;
                break;
            }
        }
        if (rule == null) throw new IllegalStateException("approved override references missing rule: " + override.ruleId());
        if (override.enabledOverride() != null) rule.put("enabled", override.enabledOverride());
        if (!override.parametersPatch().isEmpty()) {
            ObjectNode params = rule.with("parameters");
            override.parametersPatch().fields().forEachRemaining(e -> params.set(e.getKey(), e.getValue()));
        }
        if (!override.exclusionsPatch().isEmpty()) {
            ObjectNode exclude = rule.with("exclude");
            override.exclusionsPatch().fields().forEachRemaining(e -> {
                ArrayNode existing = exclude.has(e.getKey()) && exclude.get(e.getKey()).isArray()
                        ? (ArrayNode) exclude.get(e.getKey()) : exclude.putArray(e.getKey());
                LinkedHashSet<String> values = new LinkedHashSet<>();
                existing.forEach(v -> values.add(v.asText()));
                e.getValue().forEach(v -> values.add(v.asText()));
                existing.removeAll();
                values.forEach(existing::add);
            });
        }
    }

    private void validatePatch(RuleOverride override) {
        if (override.parametersPatch() == null || !override.parametersPatch().isObject())
            throw new IllegalArgumentException("parameters patch must be a JSON object");
        if (override.exclusionsPatch() == null || !override.exclusionsPatch().isObject())
            throw new IllegalArgumentException("exclusions patch must be a JSON object");
        JsonNode validated = validateExclusions(override.exclusionsPatch());
        if (!validated.equals(override.exclusionsPatch()))
            throw new IllegalArgumentException("invalid exclusions patch");
        if (!override.parametersPatch().isEmpty()) {
            ManagedRule base = current(override.ruleId());
            ObjectNode merged = base.parameters().deepCopy();
            override.parametersPatch().fields().forEachRemaining(e -> merged.set(e.getKey(), e.getValue()));
            validateParametersAgainstEngine(base.engineRuleId(), merged);
        }
    }

    private void refreshDesiredStates() {
        List<String> agents = jdbc.query("SELECT agent_id FROM agents WHERE status='ACTIVE' ORDER BY agent_id",
                (rs, n) -> rs.getString(1));
        for (String agentId : agents) upsertDesiredState(agentId, effectiveForAgent(agentId));
    }

    private void upsertDesiredState(String agentId, EffectiveRuleSet effective) {
        jdbc.update("""
                INSERT INTO agent_rule_state(agent_id,desired_revision,desired_sha256,status,updated_at)
                VALUES (?,?,?,CASE WHEN ?=COALESCE((SELECT active_sha256 FROM agent_rule_state ars WHERE ars.agent_id=?),'') THEN 'ACTIVE' ELSE 'STALE' END,now())
                ON CONFLICT(agent_id) DO UPDATE SET desired_revision=excluded.desired_revision,
                    desired_sha256=excluded.desired_sha256,
                    status=CASE WHEN agent_rule_state.active_sha256=excluded.desired_sha256 THEN 'ACTIVE' ELSE 'STALE' END,
                    updated_at=now()
                """, agentId, effective.revision(), effective.sha256(), effective.sha256(), agentId);
    }

    private void ensureAgentActive(String agentId) {
        Integer count = jdbc.queryForObject("SELECT count(*) FROM agents WHERE agent_id=? AND status='ACTIVE'", Integer.class, agentId);
        if (count == null || count != 1) throw new IllegalArgumentException("endpoint is not active: " + agentId);
    }

    private void ensureRuleInActiveBundle(String ruleId) {
        JsonNode array = active().bundle().get("rules");
        if (array == null || !array.isArray()) throw new IllegalStateException("active rule bundle has no rules array");
        for (JsonNode item : array) if (ruleId.equals(item.path("id").asText())) return;
        throw new IllegalArgumentException("override rule is not present in the active published bundle: " + ruleId);
    }

    private void auditOverride(String eventType, RuleOverride override, String actor, EffectiveRuleSet effective) {
        ObjectNode details = json.createObjectNode();
        details.put("override_id", override.overrideId());
        details.put("scope_type", override.scopeType());
        details.put("scope_id", override.scopeId());
        details.put("rule_id", override.ruleId());
        details.put("actor", actorValue(actor));
        details.put("effective_revision", effective.revision());
        details.put("effective_sha256", effective.sha256());
        details.put("approved_override_count", effective.appliedOverrideIds().size());
        jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES (?,?,?::jsonb)",
                eventType, override.scopeId(), write(details));
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
        Set<String> expectedNames = new java.util.HashSet<>();
        schema.fieldNames().forEachRemaining(expectedNames::add);
        Set<String> suppliedNames = new java.util.HashSet<>();
        parameters.fieldNames().forEachRemaining(suppliedNames::add);
        if (!expectedNames.equals(suppliedNames))
            throw new IllegalArgumentException("parameters for " + engineRuleId + " must contain exactly: " + expectedNames);
        for (String field : expectedNames) {
            JsonNode expectedValue = schema.get(field);
            JsonNode supplied = parameters.get(field);
            boolean compatible = (expectedValue.isNumber() && supplied.isNumber())
                    || (expectedValue.isBoolean() && supplied.isBoolean())
                    || (expectedValue.isTextual() && supplied.isTextual())
                    || (expectedValue.isArray() && supplied.isArray());
            if (!compatible) throw new IllegalArgumentException("parameter " + field + " has the wrong JSON type");
            if (expectedValue.isArray()) for (JsonNode item : supplied)
                if (!item.isTextual()) throw new IllegalArgumentException("array parameter " + field + " must contain strings");
        }
    }

    private JsonNode validateExclusions(JsonNode candidate) {
        JsonNode exclusions = candidate == null ? json.createObjectNode() : candidate;
        if (!exclusions.isObject()) throw new IllegalArgumentException("exclude must be a JSON object");
        java.util.Iterator<String> fields = exclusions.fieldNames();
        while (fields.hasNext()) {
            String field = fields.next();
            if (!EXCLUSION_FIELDS.contains(field)) throw new IllegalArgumentException("unsupported exclusion field: " + field);
            JsonNode values = exclusions.get(field);
            if (!values.isArray()) throw new IllegalArgumentException("exclude." + field + " must be an array of strings");
            for (JsonNode item : values) {
                if (!item.isTextual() || item.asText().isBlank())
                    throw new IllegalArgumentException("exclude." + field + " must contain non-empty strings");
                if (field.equals("directions") && !DIRECTIONS.contains(item.asText().toLowerCase(Locale.ROOT)))
                    throw new IllegalArgumentException("exclude.directions accepts inbound, outbound, or unknown");
            }
        }
        return exclusions.deepCopy();
    }

    private ManagedRule current(String id) {
        List<ManagedRule> rows = jdbc.query("""
                SELECT rule_id,revision,origin,engine_rule_id,name,category,severity,enabled,
                       parameters_json::text,exclusions_json::text,created_by,created_at
                FROM rule_definitions WHERE rule_id=? ORDER BY revision DESC LIMIT 1
                """, (rs, n) -> new ManagedRule(rs.getString(1), rs.getLong(2), rs.getString(3), rs.getString(4),
                rs.getString(5), rs.getString(6), rs.getString(7), rs.getBoolean(8), parse(rs.getString(9)),
                parse(rs.getString(10)), rs.getString(11), instant(rs.getTimestamp(12))), id);
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
    public record EffectiveRuleSet(String agentId, long revision, String version, String sha256,
                                   JsonNode bundle, String bundleText, List<Long> appliedOverrideIds) {}
    public record RuleOverride(long overrideId, String scopeType, String scopeId, String ruleId,
                               Boolean enabledOverride, JsonNode parametersPatch, JsonNode exclusionsPatch,
                               String status, Long sourceFeedbackId, String reason, String createdBy,
                               Instant createdAt, Instant approvedAt, String endpointName) {}
}
