package dev.neta.coordinator.rules;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** RM3.6 deterministic platform profiles layered before analyst endpoint overrides/baselines. */
@Service
public class PlatformProfileService {
    private static final int PROFILE_VERSION = 1;
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
        return List.of(
                new ProfileDefinition("base", PROFILE_VERSION, "Base / strict", "No platform-specific deltas; use the published fleet policy unchanged."),
                new ProfileDefinition("linux-server", PROFILE_VERSION, "Linux server", "Conservative server defaults with higher process burst thresholds."),
                new ProfileDefinition("linux-desktop", PROFILE_VERSION, "Linux desktop", "Desktop-oriented process burst thresholds to reduce routine application fanout noise."),
                new ProfileDefinition("wsl", PROFILE_VERSION, "WSL", "Linux-under-Windows defaults including known WSL parent plumbing and desktop-like burst thresholds."),
                new ProfileDefinition("windows", PROFILE_VERSION, "Windows", "Windows-oriented process burst thresholds while preserving trusted evaluator semantics."));
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
        String actorValue = actor == null || actor.isBlank() ? "operator" : actor.trim();

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
                    REASON_PREFIX + profile + "/v" + PROFILE_VERSION, actorValue);
            if (id != null) {
                rules.approveEndpointOverride(id, actorValue);
                newOverrides.add(id);
            }
        }

        jdbc.update("""
                INSERT INTO endpoint_platform_profiles(agent_id,profile_id,profile_version,assigned_by,assigned_at,updated_at)
                VALUES (?,?,?,?,now(),now())
                ON CONFLICT(agent_id) DO UPDATE SET profile_id=EXCLUDED.profile_id,
                    profile_version=EXCLUDED.profile_version,assigned_by=EXCLUDED.assigned_by,
                    assigned_at=now(),updated_at=now()
                """, agentId, profile, PROFILE_VERSION, actorValue);

        RuleManagementService.EffectiveRuleSet effective = rules.effectiveForAgent(agentId);
        jdbc.update("""
                INSERT INTO agent_rule_state(agent_id,desired_revision,desired_sha256,status,updated_at)
                VALUES (?,?,?,'STALE',now())
                ON CONFLICT(agent_id) DO UPDATE SET desired_revision=EXCLUDED.desired_revision,
                    desired_sha256=EXCLUDED.desired_sha256,
                    status=CASE WHEN agent_rule_state.active_sha256=EXCLUDED.desired_sha256 THEN 'ACTIVE' ELSE 'STALE' END,
                    last_error=NULL,updated_at=now()
                """, agentId, effective.revision(), effective.sha256());

        String details = write(Map.of("profile_id", profile, "profile_version", PROFILE_VERSION,
                "override_ids", newOverrides, "desired_revision", effective.revision(), "desired_sha256", effective.sha256(),
                "actor", actorValue));
        jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES ('PLATFORM_PROFILE_ASSIGNED',?,?::jsonb)", agentId, details);
        return assignments().stream().filter(a -> a.agentId().equals(agentId)).findFirst().orElseThrow();
    }

    public EffectiveProfile effective(String agentId) {
        EndpointProfile assignment = assignments().stream().filter(a -> a.agentId().equals(agentId)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("active endpoint not found: " + agentId));
        RuleManagementService.EffectiveRuleSet effective = rules.effectiveForAgent(agentId);
        String profile = assignment.profileId() == null ? "base" : assignment.profileId();
        int version = assignment.profileVersion() == null ? PROFILE_VERSION : assignment.profileVersion();
        return new EffectiveProfile(agentId, assignment.endpointName(), profile, version,
                effective.revision(), effective.version(), effective.sha256(), effective.appliedOverrideIds());
    }

    private List<Patch> patches(String profile) {
        return switch (profile) {
            case "base" -> List.of();
            case "linux-server" -> List.of(
                    patch("PROC-004", Map.of("child_count", 10), Map.of()),
                    patch("PROC-005", Map.of("child_count", 10), Map.of()));
            case "linux-desktop" -> List.of(
                    patch("PROC-004", Map.of("child_count", 12), Map.of()),
                    patch("PROC-005", Map.of("child_count", 12), Map.of()));
            case "wsl" -> List.of(
                    patch("PROC-002", Map.of(), Map.of("parent_process_names", List.of("wsl-pro-service"))),
                    patch("PROC-004", Map.of("child_count", 12), Map.of()),
                    patch("PROC-005", Map.of("child_count", 12), Map.of()));
            case "windows" -> List.of(
                    patch("PROC-004", Map.of("child_count", 12), Map.of()),
                    patch("PROC-005", Map.of("child_count", 12), Map.of()));
            default -> throw new IllegalArgumentException("unsupported platform profile: " + profile);
        };
    }

    private Patch patch(String ruleId, Map<String, ?> parameters, Map<String, ?> exclusions) {
        return new Patch(ruleId, write(parameters), write(exclusions));
    }

    private String normalizeProfile(String value) {
        String profile = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        boolean valid = definitions().stream().anyMatch(d -> d.id().equals(profile));
        if (!valid) throw new IllegalArgumentException("unsupported platform profile: " + value);
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

    private String write(Object value) {
        try { return json.writeValueAsString(value); }
        catch (Exception e) { throw new IllegalStateException("platform profile payload cannot be serialized", e); }
    }

    private static Instant instant(java.sql.Timestamp value) { return value == null ? null : value.toInstant(); }

    private record Patch(String ruleId, String parametersJson, String exclusionsJson) {}
    public record ProfileDefinition(String id, int version, String name, String description) {}
    public record EndpointProfile(String agentId, String endpointName, String os, String arch,
                                  String profileId, Integer profileVersion, String assignedBy,
                                  Instant assignedAt, Instant updatedAt, String suggestedProfile) {}
    public record EffectiveProfile(String agentId, String endpointName, String profileId, int profileVersion,
                                   long ruleSetRevision, String ruleSetVersion, String effectiveSha256,
                                   List<Long> appliedOverrideIds) {}
}
