package dev.neta.coordinator.api;

import dev.neta.coordinator.security.PeerCertificateService;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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
public class YaraXContentController {
    private static final String ADMIN_HEADER = "X-NETA-Admin-Token";
    private static final int MAX_CONTENT_BYTES = 1024 * 1024;
    private final JdbcTemplate jdbc;
    private final PeerCertificateService certificates;
    private final String adminToken;

    public YaraXContentController(JdbcTemplate jdbc, PeerCertificateService certificates,
                                  @Value("${NETA_OPERATOR_ADMIN_TOKEN:}") String adminToken) {
        this.jdbc = jdbc;
        this.certificates = certificates;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    @GetMapping("/operator/yarax/content")
    public Map<String,Object> overview(@RequestHeader(value = ADMIN_HEADER, required = false) String token) {
        requireAdmin(token);
        var desired = jdbc.queryForMap("SELECT target_bundle_id,previous_bundle_id,rollout_percent,updated_by,updated_at FROM yarax_content_desired WHERE singleton=1");
        var bundles = jdbc.queryForList("SELECT bundle_id,revision,sha256,content_bytes,status,created_by,created_at,activated_at FROM yarax_content_bundles ORDER BY revision DESC LIMIT 50");
        var agents = jdbc.queryForList("""
            SELECT a.agent_id,a.display_name,a.agent_os AS platform,a.agent_arch AS arch,
                   s.installed_bundle_id,s.active_bundle_id,s.active_revision,s.active_sha256,
                   s.desired_bundle_id,COALESCE(s.state,'UNKNOWN') AS state,s.error,s.last_ack_at,s.updated_at
              FROM agents a LEFT JOIN yarax_content_agent_state s ON s.agent_id=a.agent_id
             WHERE a.status='ACTIVE' ORDER BY a.display_name,a.agent_id
            """);
        return Map.of("desired", desired, "bundles", bundles, "agents", agents);
    }

    @PostMapping("/operator/yarax/content/publish")
    public Map<String,Object> publish(@RequestHeader(value = ADMIN_HEADER, required = false) String token,
                                      @RequestHeader(value = "X-NETA-Actor", required = false) String actor,
                                      @RequestBody PublishRequest request) {
        requireAdmin(token);
        String bundleId = required(request.bundleId(), "bundleId");
        if (!bundleId.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")) bad("invalid bundleId");
        String content = request.content();
        if (content == null || content.isBlank()) bad("content is required");
        int bytes = content.getBytes(StandardCharsets.UTF_8).length;
        if (bytes > MAX_CONTENT_BYTES) bad("YARA content exceeds 1 MiB limit");
        String sha = sha256(content);
        String by = actor == null || actor.isBlank() ? "operator" : actor;

        var existing = jdbc.query("SELECT revision,sha256 FROM yarax_content_bundles WHERE bundle_id=?",
                (rs,n) -> new Existing(rs.getLong("revision"), rs.getString("sha256")), bundleId);
        long revision;
        if (!existing.isEmpty()) {
            if (!existing.getFirst().sha256().equals(sha))
                throw new ResponseStatusException(HttpStatus.CONFLICT, "bundleId already exists with different content");
            revision = existing.getFirst().revision();
        } else {
            revision = jdbc.queryForObject("""
                INSERT INTO yarax_content_bundles(bundle_id,content,sha256,content_bytes,status,created_by)
                VALUES (?,?,?,?,'AVAILABLE',?) RETURNING revision
                """, Long.class, bundleId, content, sha, bytes, by);
        }
        int rollout = request.rolloutPercent() == null ? 5 : request.rolloutPercent();
        activate(bundleId, rollout, by);
        return Map.of("accepted", true, "bundleId", bundleId, "revision", revision,
                      "sha256", sha, "contentBytes", bytes, "rolloutPercent", rollout);
    }

    @PostMapping("/operator/yarax/content/rollout")
    public Map<String,Object> rollout(@RequestHeader(value = ADMIN_HEADER, required = false) String token,
                                      @RequestHeader(value = "X-NETA-Actor", required = false) String actor,
                                      @RequestBody RolloutRequest request) {
        requireAdmin(token);
        String bundleId = required(request.bundleId(), "bundleId");
        Integer exists = jdbc.queryForObject("SELECT count(*) FROM yarax_content_bundles WHERE bundle_id=?", Integer.class, bundleId);
        if (exists == null || exists == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown YARA content bundle");
        String by = actor == null || actor.isBlank() ? "operator" : actor;
        activate(bundleId, request.rolloutPercent(), by);
        return Map.of("accepted", true, "bundleId", bundleId, "rolloutPercent", request.rolloutPercent());
    }

    @PostMapping(value="/agent/yarax/content/fetch", produces=MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> fetch(HttpServletRequest request) {
        String agentId = authenticatedAgent(request);
        var desired = jdbc.queryForMap("SELECT target_bundle_id,rollout_percent FROM yarax_content_desired WHERE singleton=1");
        String target = (String) desired.get("target_bundle_id");
        if (target == null) return ResponseEntity.noContent().build();
        int percent = ((Number) desired.get("rollout_percent")).intValue();
        boolean selected = percent >= 100 || cohort(agentId) < percent;
        if (!selected) return ResponseEntity.noContent().build();

        String os = jdbc.queryForObject("SELECT agent_os FROM agents WHERE agent_id=?", String.class, agentId);
        if (os != null && os.toLowerCase().contains("windows")) {
            jdbc.update("""
                INSERT INTO yarax_content_agent_state(agent_id,desired_bundle_id,state,error,updated_at)
                VALUES (?,?,'UNSUPPORTED','YARA-X artifact scanning is not enabled on Windows yet',now())
                ON CONFLICT(agent_id) DO UPDATE SET desired_bundle_id=excluded.desired_bundle_id,state='UNSUPPORTED',error=excluded.error,updated_at=now()
                """, agentId, target);
            return ResponseEntity.noContent().build();
        }

        Integer alreadyActive = jdbc.queryForObject("""
            SELECT count(*) FROM yarax_content_agent_state
             WHERE agent_id=? AND active_bundle_id=? AND state='ACTIVE'
            """, Integer.class, agentId, target);
        if (alreadyActive != null && alreadyActive > 0) return ResponseEntity.noContent().build();

        var bundle = jdbc.queryForMap("SELECT bundle_id,revision,sha256,content FROM yarax_content_bundles WHERE bundle_id=?", target);
        jdbc.update("""
            INSERT INTO yarax_content_agent_state(agent_id,desired_bundle_id,state,updated_at)
            VALUES (?,?,'STALE',now()) ON CONFLICT(agent_id) DO UPDATE SET desired_bundle_id=excluded.desired_bundle_id,
              state=CASE WHEN yarax_content_agent_state.active_bundle_id=excluded.desired_bundle_id THEN 'ACTIVE' ELSE 'STALE' END,
              error=NULL,updated_at=now()
            """, agentId, target);
        String envelope = "NETA-YARAX-CONTENT/1\n" +
                "bundle-id:" + bundle.get("bundle_id") + "\n" +
                "revision:" + bundle.get("revision") + "\n" +
                "sha256:" + bundle.get("sha256") + "\n\n" + bundle.get("content");
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(envelope);
    }

    @PostMapping("/agent/yarax/content/ack")
    public Map<String,Object> ack(HttpServletRequest servletRequest, @RequestBody AckRequest request) {
        String agentId = authenticatedAgent(servletRequest);
        String bundleId = required(request.bundleId(), "bundleId");
        String state = required(request.state(), "state").toUpperCase();
        if (!List.of("DOWNLOADING","INSTALLED","ACTIVE","APPLY_FAILED","UNSUPPORTED").contains(state)) bad("invalid state");
        if (request.sha256() != null && !request.sha256().isBlank()) validateSha(request.sha256());
        if ((state.equals("INSTALLED") || state.equals("ACTIVE"))) {
            var expected = jdbc.query("SELECT revision,sha256 FROM yarax_content_bundles WHERE bundle_id=?",
                    (rs,n) -> new Existing(rs.getLong("revision"),rs.getString("sha256")), bundleId);
            if (expected.isEmpty()) bad("unknown bundleId");
            if (request.revision() == null || request.revision() != expected.getFirst().revision() ||
                request.sha256() == null || !request.sha256().equalsIgnoreCase(expected.getFirst().sha256()))
                bad("YARA content acknowledgement does not match coordinator-pinned revision/SHA-256");
        }
        jdbc.update("""
            INSERT INTO yarax_content_agent_state(agent_id,installed_bundle_id,active_bundle_id,active_revision,active_sha256,desired_bundle_id,state,error,last_ack_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,now(),now()) ON CONFLICT(agent_id) DO UPDATE SET
              installed_bundle_id=excluded.installed_bundle_id,active_bundle_id=excluded.active_bundle_id,
              active_revision=excluded.active_revision,active_sha256=excluded.active_sha256,
              desired_bundle_id=excluded.desired_bundle_id,state=excluded.state,error=excluded.error,last_ack_at=now(),updated_at=now()
            """, agentId,
            state.equals("INSTALLED") || state.equals("ACTIVE") ? bundleId : null,
            state.equals("ACTIVE") ? bundleId : null,
            state.equals("ACTIVE") ? request.revision() : null,
            state.equals("ACTIVE") ? request.sha256() : null,
            bundleId,state,request.error());
        return Map.of("accepted", true, "agentId", agentId, "bundleId", bundleId, "state", state);
    }

    private void activate(String bundleId, int percent, String actor) {
        if (percent < 0 || percent > 100) bad("rolloutPercent must be between 0 and 100");
        jdbc.update("UPDATE yarax_content_bundles SET status=CASE WHEN bundle_id=? THEN 'ACTIVE' WHEN status='ACTIVE' THEN 'AVAILABLE' ELSE status END,activated_at=CASE WHEN bundle_id=? THEN now() ELSE activated_at END", bundleId,bundleId);
        jdbc.update("UPDATE yarax_content_desired SET previous_bundle_id=CASE WHEN target_bundle_id IS DISTINCT FROM ? THEN target_bundle_id ELSE previous_bundle_id END,target_bundle_id=?,rollout_percent=?,updated_by=?,updated_at=now() WHERE singleton=1", bundleId,bundleId,percent,actor);
    }

    private String authenticatedAgent(HttpServletRequest request) {
        String fingerprint = certificates.sha256Fingerprint(request).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "agent mTLS certificate is required"));
        List<String> agents = jdbc.query("SELECT agent_id FROM agents WHERE certificate_sha256=? AND status='ACTIVE' LIMIT 2", (rs,n)->rs.getString(1), fingerprint);
        if (agents.size()!=1) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "agent certificate is not bound to one active endpoint");
        return agents.getFirst();
    }

    private void requireAdmin(String supplied) {
        if (adminToken.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "YARA content administration is disabled");
        if (!MessageDigest.isEqual(adminToken.getBytes(StandardCharsets.UTF_8), (supplied==null?"":supplied).getBytes(StandardCharsets.UTF_8)))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid operator admin token");
    }
    private static int cohort(String agentId) { return Math.floorMod(agentId.hashCode(),100); }
    private static String required(String value,String name){ if(value==null||value.isBlank()) bad(name+" is required"); return value.trim(); }
    private static void validateSha(String sha){ if(sha==null||!sha.matches("[0-9a-fA-F]{64}")) bad("SHA-256 must be 64 hex characters"); }
    private static void bad(String message){ throw new ResponseStatusException(HttpStatus.BAD_REQUEST,message); }
    private static String sha256(String content) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable",e); }
    }

    public record PublishRequest(String bundleId,String content,Integer rolloutPercent) {}
    public record RolloutRequest(String bundleId,int rolloutPercent) {}
    public record AckRequest(String bundleId,Long revision,String sha256,String state,String error) {}
    private record Existing(long revision,String sha256) {}
}
