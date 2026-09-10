package dev.neta.coordinator.api;

import dev.neta.coordinator.security.PeerCertificateService;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1")
public class YaraXRuntimeController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";
    private final JdbcTemplate jdbc;
    private final PeerCertificateService certificates;
    private final String adminToken;

    public YaraXRuntimeController(JdbcTemplate jdbc, PeerCertificateService certificates,
                                  @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.jdbc = jdbc;
        this.certificates = certificates;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @GetMapping("/operator/yarax/runtime")
    public Map<String,Object> overview(@RequestHeader(value = ADMIN_HEADER, required = false) String token) {
        requireAdmin(token);
        var desired = jdbc.queryForMap("SELECT target_version, previous_version, rollout_percent, updated_by, updated_at FROM yarax_runtime_desired WHERE singleton=1");
        var releases = jdbc.queryForList("SELECT version,source_ref,release_base_url,priority,x86_64_sha256,arm64_sha256,status,created_by,created_at,activated_at FROM yarax_runtime_releases ORDER BY created_at DESC LIMIT 50");
        var agents = jdbc.queryForList("""
            SELECT a.agent_id, a.display_name, a.agent_os AS platform, a.agent_arch AS arch,
                   s.installed_version, s.active_version, s.active_sha256,
                   s.desired_version, COALESCE(s.state,'UNKNOWN') AS state,
                   s.error, s.last_ack_at, s.updated_at
            FROM agents a LEFT JOIN yarax_agent_runtime_state s ON s.agent_id=a.agent_id
            WHERE a.status='ACTIVE' ORDER BY a.display_name, a.agent_id
            """);
        return Map.of("desired", desired, "releases", releases, "agents", agents);
    }

    @PostMapping("/operator/yarax/runtime/publish")
    public Map<String,Object> publish(@RequestHeader(value = ADMIN_HEADER, required = false) String token,
                                      @RequestHeader(value = "X-NETA-Actor", required = false) String actor,
                                      @RequestBody PublishRequest request) {
        requireAdmin(token);
        String version = required(request.version(), "version");
        if (!version.matches("[0-9]+\\.[0-9]+\\.[0-9]+([.-][A-Za-z0-9._-]+)?")) bad("invalid version");
        String priority = request.priority() == null ? "NORMAL" : request.priority().trim().toUpperCase();
        if (!List.of("NORMAL","HIGH","EMERGENCY").contains(priority)) bad("invalid priority");
        validateSha(request.x86_64Sha256()); validateSha(request.arm64Sha256());
        String source = required(request.sourceRef(), "sourceRef");
        String base = required(request.releaseBaseUrl(), "releaseBaseUrl");
        if (!base.equals("https://github.com/zelinsky-alexander/neta-agent/releases/download/yarax-runtime-v" + version)) bad("releaseBaseUrl must reference the matching NETA GitHub release");
        String by = actor == null || actor.isBlank() ? "operator" : actor;
        jdbc.update("""
            INSERT INTO yarax_runtime_releases(version,source_ref,release_base_url,priority,x86_64_sha256,arm64_sha256,status,created_by)
            VALUES (?,?,?,?,?,?, 'AVAILABLE',?)
            ON CONFLICT(version) DO UPDATE SET source_ref=excluded.source_ref,release_base_url=excluded.release_base_url,
              priority=excluded.priority,x86_64_sha256=excluded.x86_64_sha256,arm64_sha256=excluded.arm64_sha256
            """, version, source, base, priority, request.x86_64Sha256().toLowerCase(), request.arm64Sha256().toLowerCase(), by);
        int rollout = request.rolloutPercent() == null ? (priority.equals("EMERGENCY") ? 25 : 5) : request.rolloutPercent();
        activate(version, rollout, by);
        return Map.of("accepted", true, "version", version, "priority", priority, "rolloutPercent", rollout);
    }

    @PostMapping("/operator/yarax/runtime/rollout")
    public Map<String,Object> rollout(@RequestHeader(value = ADMIN_HEADER, required = false) String token,
                                      @RequestHeader(value = "X-NETA-Actor", required = false) String actor,
                                      @RequestBody RolloutRequest request) {
        requireAdmin(token);
        String version = required(request.version(), "version");
        int percent = request.rolloutPercent();
        if (percent < 0 || percent > 100) bad("rolloutPercent must be between 0 and 100");
        Integer exists = jdbc.queryForObject("SELECT count(*) FROM yarax_runtime_releases WHERE version=?", Integer.class, version);
        if (exists == null || exists == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown YARA-X runtime version");
        String by = actor == null || actor.isBlank() ? "operator" : actor;
        activate(version, percent, by);
        return Map.of("accepted", true, "version", version, "rolloutPercent", percent);
    }

    @GetMapping("/agent/yarax/runtime/current")
    public AgentRuntime current(HttpServletRequest request) {
        String agentId = authenticatedAgent(request);
        var desired = jdbc.queryForMap("SELECT target_version,previous_version,rollout_percent FROM yarax_runtime_desired WHERE singleton=1");
        String target = (String) desired.get("target_version");
        if (target == null) return new AgentRuntime(agentId, false, null, null, null, "NORMAL", 0);
        int percent = ((Number) desired.get("rollout_percent")).intValue();
        var release = jdbc.queryForMap("SELECT version,release_base_url,priority,x86_64_sha256,arm64_sha256 FROM yarax_runtime_releases WHERE version=?", target);
        String priority = (String) release.get("priority");
        boolean selected = priority.equals("EMERGENCY") || percent >= 100 || cohort(agentId) < percent;
        if (!selected) return new AgentRuntime(agentId, false, target, null, null, priority, percent);
        String arch = jdbc.queryForObject("SELECT agent_arch FROM agents WHERE agent_id=?", String.class, agentId);
        if (arch == null || arch.isBlank()) return new AgentRuntime(agentId, false, target, null, null, priority, percent);
        String sha;
        if (arch.equalsIgnoreCase("arm64") || arch.equalsIgnoreCase("aarch64")) sha = (String) release.get("arm64_sha256");
        else if (arch.equalsIgnoreCase("amd64") || arch.equalsIgnoreCase("x86_64")) sha = (String) release.get("x86_64_sha256");
        else {
            jdbc.update("""
                INSERT INTO yarax_agent_runtime_state(agent_id,desired_version,state,error,updated_at)
                VALUES (?,?,'UNSUPPORTED',?,now()) ON CONFLICT(agent_id) DO UPDATE SET desired_version=excluded.desired_version,state='UNSUPPORTED',error=excluded.error,updated_at=now()
                """, agentId, target, "unsupported YARA-X runtime architecture: " + arch);
            return new AgentRuntime(agentId, false, target, null, null, priority, percent);
        }
        jdbc.update("""
            INSERT INTO yarax_agent_runtime_state(agent_id,desired_version,state,updated_at)
            VALUES (?,?,'STALE',now()) ON CONFLICT(agent_id) DO UPDATE SET desired_version=excluded.desired_version,
              state=CASE WHEN yarax_agent_runtime_state.active_version=excluded.desired_version THEN 'ACTIVE' ELSE 'STALE' END, updated_at=now()
            """, agentId, target);
        return new AgentRuntime(agentId, true, target, (String) release.get("release_base_url"), sha, priority, percent);
    }

    @PostMapping("/agent/yarax/runtime/ack")
    public Map<String,Object> ack(HttpServletRequest servletRequest, @RequestBody AckRequest request) {
        String agentId = authenticatedAgent(servletRequest);
        String state = required(request.state(), "state").toUpperCase();
        if (!List.of("DOWNLOADING","INSTALLED","ACTIVE","APPLY_FAILED","UNSUPPORTED").contains(state)) bad("invalid state");
        if (request.activeSha256() != null && !request.activeSha256().isBlank()) validateSha(request.activeSha256());
        jdbc.update("""
            INSERT INTO yarax_agent_runtime_state(agent_id,installed_version,active_version,active_sha256,desired_version,state,error,last_ack_at,updated_at)
            VALUES (?,?,?,?,?,?,?,now(),now()) ON CONFLICT(agent_id) DO UPDATE SET
              installed_version=excluded.installed_version,active_version=excluded.active_version,active_sha256=excluded.active_sha256,
              desired_version=excluded.desired_version,state=excluded.state,error=excluded.error,last_ack_at=now(),updated_at=now()
            """, agentId, request.installedVersion(), request.activeVersion(), request.activeSha256(), request.desiredVersion(), state, request.error());
        return Map.of("accepted", true, "agentId", agentId, "state", state);
    }

    private void activate(String version, int percent, String actor) {
        if (percent < 0 || percent > 100) bad("rolloutPercent must be between 0 and 100");
        jdbc.update("UPDATE yarax_runtime_releases SET status=CASE WHEN version=? THEN 'ACTIVE' WHEN status='ACTIVE' THEN 'AVAILABLE' ELSE status END, activated_at=CASE WHEN version=? THEN now() ELSE activated_at END", version, version);
        jdbc.update("UPDATE yarax_runtime_desired SET previous_version=CASE WHEN target_version IS DISTINCT FROM ? THEN target_version ELSE previous_version END,target_version=?,rollout_percent=?,updated_by=?,updated_at=now() WHERE singleton=1", version, version, percent, actor);
    }

    private String authenticatedAgent(HttpServletRequest request) {
        String fingerprint = certificates.sha256Fingerprint(request).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "agent mTLS certificate is required"));
        List<String> agents = jdbc.query("SELECT agent_id FROM agents WHERE certificate_sha256=? AND status='ACTIVE' LIMIT 2", (rs,n)->rs.getString(1), fingerprint);
        if (agents.size()!=1) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "agent certificate is not bound to one active endpoint");
        return agents.getFirst();
    }
    private static int cohort(String agentId) { return Math.floorMod(agentId.hashCode(), 100); }
    private void requireAdmin(String supplied) {
        if (adminToken.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "runtime administration is disabled");
        if (!MessageDigest.isEqual(adminToken.getBytes(StandardCharsets.UTF_8), (supplied==null?"":supplied).getBytes(StandardCharsets.UTF_8)))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
    }
    private static String required(String value,String name){ if(value==null||value.isBlank()) bad(name+" is required"); return value.trim(); }
    private static void validateSha(String sha){ if(sha==null||!sha.matches("[0-9a-fA-F]{64}")) bad("SHA-256 must be 64 hex characters"); }
    private static void bad(String message){ throw new ResponseStatusException(HttpStatus.BAD_REQUEST,message); }

    public record PublishRequest(String version,String sourceRef,String releaseBaseUrl,String priority,String x86_64Sha256,String arm64Sha256,Integer rolloutPercent) {}
    public record RolloutRequest(String version,int rolloutPercent) {}
    public record AckRequest(String installedVersion,String activeVersion,String activeSha256,String desiredVersion,String state,String error) {}
    public record AgentRuntime(String agentId,boolean updateAvailable,String version,String releaseBaseUrl,String sha256,String priority,int rolloutPercent) {}
}
