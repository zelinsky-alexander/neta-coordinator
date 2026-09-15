package dev.neta.coordinator.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Deterministic platform profiles layered before analyst endpoint overrides/baselines. */
@Service
public class PlatformProfileService {
    private static final String REASON_PREFIX = "RM3.6 profile:";

    private final JdbcTemplate jdbc;
    private final RuleManagementService rules;
    private final ObjectMapper json;

    public PlatformProfileService(JdbcTemplate jdbc, RuleManagementService rules, ObjectMapper json) {
        this.jdbc = jdbc;
        this.rules = rules;
        this.json = json;
    }

    public List<ProfileDefinition> definitions() {
        return jdbc.query("""
                SELECT profile_id,version,name,description,updated_by,updated_at
                  FROM platform_profile_catalog ORDER BY profile_id
                """, (rs, n) -> new ProfileDefinition(rs.getString(1), rs.getInt(2), rs.getString(3), rs.getString(4),
                rs.getString(5), instant(rs.getTimestamp(6))));
    }

    public List<ProfileRulePatch> rulePatches() {
        return jdbc.query("""
                SELECT profile_id,rule_id,parameters_patch::text,exclusions_patch::text,updated_by,updated_at
                  FROM platform_profile_rule_patches ORDER BY profile_id,rule_id
                """, (rs, n) -> new ProfileRulePatch(rs.getString(1), rs.getString(2), parse(rs.getString(3)),
                parse(rs.getString(4)), rs.getString(5), instant(rs.getTimestamp(6))));
    }

    public List<EndpointProfile> assignments() {
        return jdbc.query("""
                SELECT a.agent_id,coalesce(a.display_name,a.agent_id),a.agent_os,a.agent_arch,
                       p.profile_id,p.profile_version,p.assigned_by,p.assigned_at,p.updated_at
                  FROM agents a
                  LEFT JOIN endpoint_platform_profiles p ON p.agent_id=a.agent_id
                 WHERE a.status='ACTIVE'
                 ORDER BY coalesce(a.display_name,a.agent_id),a.agent_id
                """, (rs, n) -> {
            String os = rs.getString(3);
            String name = rs.getString(2);
            String assigned = rs.getString(5);
            return new EndpointProfile(rs.getString(1), name, os, rs.getString(4),
                    assigned, rs.getObject(6, Integer.class), rs.getString(7),
                    instant(rs.getTimestamp(8)), instant(rs.getTimestamp(9)), suggest(os, name));
        });
    }

    @Transactional
    public EndpointProfile assign(String agentId, String requestedProfile, String actor) {
        String profile = normalizeProfile(requestedProfile);
        ensureActiveAgent(agentId);
        String actorValue = actorValue(actor);
        int version = profileVersion(profile);
        materialize(agentId, profile, version, actorValue);

        jdbc.update("""
                INSERT INTO endpoint_platform_profiles(agent_id,profile_id,profile_version,assigned_by,assigned_at,updated_at)
                VALUES (?,?,?,?,now(),now())
                ON CONFLICT(agent_id) DO UPDATE SET profile_id=EXCLUDED.profile_id,
                    profile_version=EXCLUDED.profile_version,assigned_by=EXCLUDED.assigned_by,
                    assigned_at=now(),updated_at=now()
                """, agentId, profile, version, actorValue);
        auditAssignment(agentId, profile, version, actorValue);
        return assignments().stream().filter(a -> a.agentId().equals(agentId)).findFirst().orElseThrow();
    }

    @Transactional
    public ProfileRulePatch updateRulePatch(String requestedProfile, String ruleId,
                                            Map<String, ?> parameters, Map<String, ?> exclusions,
                                            String actor) {
        String profile = normalizeProfile(requestedProfile);
        if ("base".equals(profile)) throw new IllegalArgumentException("base profile cannot contain platform deltas");
        String rule = ruleId == null ? "" : ruleId.trim().toUpperCase(Locale.ROOT);
        if (rule.isBlank()) throw new IllegalArgumentException("ruleId is required");
        Integer ruleCount = jdbc.queryForObject("SELECT count(*) FROM rule_definitions WHERE rule_id=?", Integer.class, rule);
        if (ruleCount == null || ruleCount == 0) throw new IllegalArgumentException("rule is not in the central catalog: " + rule);
        String actorValue = actorValue(actor);
        String parametersJson = write(parameters == null ? Map.of() : parameters);
        String exclusionsJson = write(exclusions == null ? Map.of() : exclusions);
        boolean empty = isEmptyObject(parametersJson) && isEmptyObject(exclusionsJson);

        if (empty) {
            jdbc.update("DELETE FROM platform_profile_rule_patches WHERE profile_id=? AND rule_id=?", profile, rule);
        } else {
            jdbc.update("""
                    INSERT INTO platform_profile_rule_patches(profile_id,rule_id,parameters_patch,exclusions_patch,updated_by,updated_at)
                    VALUES (?,?,?::jsonb,?::jsonb,?,now())
                    ON CONFLICT(profile_id,rule_id) DO UPDATE SET
                        parameters_patch=EXCLUDED.parameters_patch,
                        exclusions_patch=EXCLUDED.exclusions_patch,
                        updated_by=EXCLUDED.updated_by,updated_at=now()
                    """, profile, rule, parametersJson, exclusionsJson, actorValue);
        }
        jdbc.update("UPDATE platform_profile_catalog SET version=version+1,updated_by=?,updated_at=now() WHERE profile_id=?",
                actorValue, profile);
        int version = profileVersion(profile);

        List<String> assignedAgents = jdbc.query("""
                SELECT p.agent_id FROM endpoint_platform_profiles p
                JOIN agents a ON a.agent_id=p.agent_id
                WHERE p.profile_id=? AND a.status='ACTIVE'
                ORDER BY p.agent_id
                """, (rs, n) -> rs.getString(1), profile);
        for (String agentId : assignedAgents) {
            materialize(agentId, profile, version, actorValue);
            jdbc.update("UPDATE endpoint_platform_profiles SET profile_version=?,updated_at=now() WHERE agent_id=?",
                    version, agentId);
        }

        String details = write(Map.of("profile_id", profile, "profile_version", version, "rule_id", rule,
                "parameters_patch", parameters == null ? Map.of() : parameters,
                "exclusions_patch", exclusions == null ? Map.of() : exclusions,
                "assigned_endpoints_recalculated", assignedAgents.size(), "actor", actorValue));
        jdbc.update("INSERT INTO audit_events(event_type,details) VALUES ('PLATFORM_PROFILE_RULE_UPDATED',?::jsonb)", details);

        if (empty) return new ProfileRulePatch(profile, rule, json.createObjectNode(), json.createObjectNode(), actorValue, Instant.now());
        return rulePatches().stream().filter(p -> p.profileId().equals(profile) && p.ruleId().equals(rule)).findFirst().orElseThrow();
    }

    public EffectiveProfile effective(String agentId) {
        EndpointProfile assignment = assignments().stream().filter(a -> a.agentId().equals(agentId)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("active endpoint not found: " + agentId));
        RuleManagementService.EffectiveRuleSet effective = rules.effectiveForAgent(agentId);
        String profile = assignment.profileId() == null ? "base" : assignment.profileId();
        int version = assignment.profileVersion() == null ? profileVersion(profile) : assignment.profileVersion();
        return new EffectiveProfile(agentId, assignment.endpointName(), profile, version,
                effective.revision(), effective.version(), effective.sha256(), effective.appliedOverrideIds());
    }

    private void materialize(String agentId, String profile, int version, String actorValue) {
        List<Long> oldOverrides = jdbc.query("""
                SELECT override_id FROM rule_overrides
                 WHERE scope_type='ENDPOINT' AND scope_id=? AND status='APPROVED'
                   AND reason LIKE 'RM3.6 profile:%'
                 ORDER BY override_id
                """, (rs, n) -> rs.getLong(1), agentId);
        for (Long id : oldOverrides) rules.retireEndpointOverride(id, actorValue);

        List<Long> newOverrides = new ArrayList<>();
        for (Patch patch : patches(profile)) {
            Long id = jdbc.queryForObject("""
                    INSERT INTO rule_overrides(scope_type,scope_id,rule_id,parameters_patch,exclusions_patch,status,reason,created_by)
                    VALUES ('ENDPOINT',?,?,?::jsonb,?::jsonb,'STAGED',?,?) RETURNING override_id
                    """, Long.class, agentId, patch.ruleId(), patch.parametersJson(), patch.exclusionsJson(),
                    REASON_PREFIX + profile + "/v" + version, actorValue);
            if (id != null) {
                rules.approveEndpointOverride(id, actorValue);
                newOverrides.add(id);
            }
        }

        RuleManagementService.EffectiveRuleSet effective = rules.effectiveForAgent(agentId);
        jdbc.update("""
                INSERT INTO agent_rule_state(agent_id,desired_revision,desired_sha256,status,updated_at)
                VALUES (?,?,?,'STALE',now())
                ON CONFLICT(agent_id) DO UPDATE SET desired_revision=EXCLUDED.desired_revision,
                    desired_sha256=EXCLUDED.desired_sha256,
                    status=CASE WHEN agent_rule_state.active_sha256=EXCLUDED.desired_sha256 THEN 'ACTIVE' ELSE 'STALE' END,
                    last_error=NULL,updated_at=now()
                """, agentId, effective.revision(), effective.sha256());
    }

    private void auditAssignment(String agentId, String profile, int version, String actorValue) {
        RuleManagementService.EffectiveRuleSet effective = rules.effectiveForAgent(agentId);
        String details = write(Map.of("profile_id", profile, "profile_version", version,
                "desired_revision", effective.revision(), "desired_sha256", effective.sha256(), "actor", actorValue));
        jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES ('PLATFORM_PROFILE_ASSIGNED',?,?::jsonb)", agentId, details);
    }

    private List<Patch> patches(String profile) {
        return jdbc.query("""
                SELECT rule_id,parameters_patch::text,exclusions_patch::text
                  FROM platform_profile_rule_patches WHERE profile_id=? ORDER BY rule_id
                """, (rs, n) -> new Patch(rs.getString(1), rs.getString(2), rs.getString(3)), profile);
    }

    private int profileVersion(String profile) {
        Integer version = jdbc.queryForObject("SELECT version FROM platform_profile_catalog WHERE profile_id=?", Integer.class, profile);
        if (version == null) throw new IllegalArgumentException("unsupported platform profile: " + profile);
        return version;
    }

    private String normalizeProfile(String value) {
        String profile = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        Integer count = jdbc.queryForObject("SELECT count(*) FROM platform_profile_catalog WHERE profile_id=?", Integer.class, profile);
        if (count == null || count != 1) throw new IllegalArgumentException("unsupported platform profile: " + value);
        return profile;
    }

    private void ensureActiveAgent(String agentId) {
        Integer count = jdbc.queryForObject("SELECT count(*) FROM agents WHERE agent_id=? AND status='ACTIVE'", Integer.class, agentId);
        if (count == null || count != 1) throw new IllegalArgumentException("active endpoint not found: " + agentId);
    }

    private String suggest(String os, String name) {
        String hint = ((os == null ? "" : os) + " " + (name == null ? "" : name)).toLowerCase(Locale.ROOT);
        if (hint.contains("wsl")) return "wsl";
        if (hint.contains("windows") || hint.matches(".*\\bwin(?:10|11|32|64)?\\b.*")) return "windows";
        if (hint.contains("linux") || hint.contains("ubuntu") || hint.contains("debian") || hint.contains("rhel") || hint.contains("fedora")) return "linux-server";
        return "base";
    }

    private String actorValue(String actor) { return actor == null || actor.isBlank() ? "operator" : actor.trim(); }

    private boolean isEmptyObject(String value) {
        try { JsonNode node = json.readTree(value); return node != null && node.isObject() && node.isEmpty(); }
        catch (Exception e) { return false; }
    }

    private JsonNode parse(String value) {
        try { return json.readTree(value == null || value.isBlank() ? "{}" : value); }
        catch (Exception e) { throw new IllegalStateException("stored platform profile JSON is invalid", e); }
    }

    private String write(Object value) {
        try { return json.writeValueAsString(value); }
        catch (Exception e) { throw new IllegalStateException("platform profile payload cannot be serialized", e); }
    }

    private static Instant instant(java.sql.Timestamp value) { return value == null ? null : value.toInstant(); }

    private record Patch(String ruleId, String parametersJson, String exclusionsJson) {}
    public record ProfileDefinition(String id, int version, String name, String description,
                                    String updatedBy, Instant updatedAt) {}
    public record ProfileRulePatch(String profileId, String ruleId, JsonNode parametersPatch,
                                   JsonNode exclusionsPatch, String updatedBy, Instant updatedAt) {}
    public record EndpointProfile(String agentId, String endpointName, String os, String arch,
                                  String profileId, Integer profileVersion, String assignedBy,
                                  Instant assignedAt, Instant updatedAt, String suggestedProfile) {}
    public record EffectiveProfile(String agentId, String endpointName, String profileId, int profileVersion,
                                   long ruleSetRevision, String ruleSetVersion, String effectiveSha256,
                                   List<Long> appliedOverrideIds) {}
}
