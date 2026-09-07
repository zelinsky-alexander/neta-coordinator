package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1")
public class PortalReadApiController {
    private static final int MAX_LIMIT = 100;
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public PortalReadApiController(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @GetMapping("/fleet/summary")
    public FleetSummary fleetSummary() {
        AgentCounts agents = jdbc.queryForObject("""
                SELECT count(*) total,
                       count(*) FILTER (WHERE status='ACTIVE') online,
                       count(*) FILTER (WHERE lower(COALESCE(agent_os,'')) LIKE 'linux%') linux,
                       count(*) FILTER (WHERE lower(COALESCE(agent_os,'')) LIKE 'windows%') windows
                FROM agents
                """, (rs,n) -> new AgentCounts(rs.getLong("total"), rs.getLong("online"), rs.getLong("linux"), rs.getLong("windows")));
        FindingCounts findings = jdbc.queryForObject("""
                SELECT count(*) total,
                       count(*) FILTER (WHERE status='ACTIVE') active,
                       count(*) FILTER (WHERE upper(COALESCE(trust_verdict,''))='SUSPICIOUS') suspicious,
                       count(*) FILTER (WHERE upper(COALESCE(trust_verdict,''))='CHANGED') changed
                FROM findings
                """, (rs,n) -> new FindingCounts(rs.getLong("total"), rs.getLong("active"), rs.getLong("suspicious"), rs.getLong("changed")));
        CertificateCounts certificates = jdbc.queryForObject("""
                SELECT
                  count(*) FILTER (WHERE status='ACTIVE' AND certificate_not_after > now() + interval '30 days') valid,
                  count(*) FILTER (WHERE status='ACTIVE' AND certificate_not_after > now() + interval '7 days' AND certificate_not_after <= now() + interval '30 days') expiring,
                  count(*) FILTER (WHERE status='ACTIVE' AND certificate_not_after > now() AND certificate_not_after <= now() + interval '7 days') critical,
                  count(*) FILTER (WHERE status='ACTIVE' AND certificate_not_after <= now()) expired,
                  count(*) FILTER (WHERE status='ACTIVE' AND certificate_not_after IS NULL) unknown
                FROM agents
                """, (rs,n) -> new CertificateCounts(rs.getLong("valid"), rs.getLong("expiring"), rs.getLong("critical"), rs.getLong("expired"), rs.getLong("unknown")));
        if (agents == null) agents = new AgentCounts(0,0,0,0);
        if (findings == null) findings = new FindingCounts(0,0,0,0);
        if (certificates == null) certificates = new CertificateCounts(0,0,0,0,0);
        return new FleetSummary(
                new FleetAgents(agents.total(), agents.online(), Math.max(0, agents.total()-agents.online()), agents.linux(), agents.windows()),
                findings, certificates);
    }

    @GetMapping("/agents")
    public Page<AgentItem> agents(@RequestParam(defaultValue="50") int limit,
                                  @RequestParam(required=false) String cursor,
                                  @RequestParam(required=false) String search,
                                  @RequestParam(required=false) String status,
                                  @RequestParam(required=false) String platform) {
        int bounded = bounded(limit);
        List<Object> args = new ArrayList<>();
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (text(search)) { where.append(" AND (lower(agent_id) LIKE lower(?) OR lower(COALESCE(display_name,'')) LIKE lower(?))"); args.add("%"+search+"%"); args.add("%"+search+"%"); }
        if (text(status)) { where.append(" AND upper(status)=upper(?)"); args.add(status); }
        if (text(platform)) { where.append(" AND lower(COALESCE(agent_os,'')) LIKE lower(?)"); args.add(platform+"%"); }
        Cursor c = decode(cursor);
        if (c != null) {
            where.append(" AND (lower(COALESCE(NULLIF(display_name,''),agent_id)), agent_id) > (?,?)");
            args.add(c.value()); args.add(c.id());
        }
        args.add(bounded + 1);
        List<AgentItem> rows = jdbc.query("""
                SELECT agent_id,display_name,status,last_seen_at,agent_version,agent_build_id,agent_git_commit,
                       agent_os,agent_arch,agent_artifact_sha256,agent_protocol_version,agent_schema_version,
                       agent_features::text AS agent_features,certificate_sha256,enrolled_at,last_sequence
                FROM agents
                """ + where + " ORDER BY lower(COALESCE(NULLIF(display_name,''),agent_id)), agent_id LIMIT ?",
                (rs,n) -> new AgentItem(rs.getString("agent_id"), display(rs.getString("display_name"),rs.getString("agent_id")),
                        rs.getString("status"), instant(rs.getTimestamp("last_seen_at")), rs.getString("agent_version"),
                        rs.getString("agent_build_id"), rs.getString("agent_git_commit"), rs.getString("agent_os"), rs.getString("agent_arch"),
                        rs.getString("agent_artifact_sha256"), rs.getObject("agent_protocol_version",Integer.class),
                        rs.getObject("agent_schema_version",Integer.class), rs.getString("agent_features"), rs.getString("certificate_sha256"),
                        instant(rs.getTimestamp("enrolled_at")), rs.getLong("last_sequence")), args.toArray());
        return page(rows, bounded, r -> encode(r.name().toLowerCase(Locale.ROOT), r.id()));
    }

    @GetMapping("/agents/{agentId}")
    public AgentItem agent(@PathVariable String agentId) {
        List<AgentItem> rows = jdbc.query("""
                SELECT agent_id,display_name,status,last_seen_at,agent_version,agent_build_id,agent_git_commit,
                       agent_os,agent_arch,agent_artifact_sha256,agent_protocol_version,agent_schema_version,
                       agent_features::text AS agent_features,certificate_sha256,enrolled_at,last_sequence
                FROM agents WHERE agent_id=? OR display_name=? ORDER BY CASE WHEN agent_id=? THEN 0 ELSE 1 END LIMIT 1
                """, (rs,n) -> new AgentItem(rs.getString("agent_id"), display(rs.getString("display_name"),rs.getString("agent_id")),
                        rs.getString("status"), instant(rs.getTimestamp("last_seen_at")), rs.getString("agent_version"), rs.getString("agent_build_id"),
                        rs.getString("agent_git_commit"), rs.getString("agent_os"), rs.getString("agent_arch"), rs.getString("agent_artifact_sha256"),
                        rs.getObject("agent_protocol_version",Integer.class), rs.getObject("agent_schema_version",Integer.class),
                        rs.getString("agent_features"), rs.getString("certificate_sha256"), instant(rs.getTimestamp("enrolled_at")), rs.getLong("last_sequence")),
                agentId, agentId, agentId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"agent not found");
        return rows.getFirst();
    }

    @GetMapping("/findings")
    public Page<FindingItem> findings(@RequestParam(defaultValue="50") int limit,
                                      @RequestParam(required=false) String cursor,
                                      @RequestParam(required=false) String agent,
                                      @RequestParam(required=false) String trust,
                                      @RequestParam(required=false) String performance,
                                      @RequestParam(required=false) String status,
                                      @RequestParam(required=false) String target) {
        int bounded = bounded(limit);
        List<Object> args = new ArrayList<>();
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (text(agent)) { where.append(" AND (f.agent_id=? OR lower(COALESCE(a.display_name,''))=lower(?))"); args.add(agent); args.add(agent); }
        if (text(trust)) { where.append(" AND upper(COALESCE(f.trust_verdict,''))=upper(?)"); args.add(trust); }
        if (text(performance)) { where.append(" AND upper(COALESCE(f.performance_verdict,''))=upper(?)"); args.add(performance); }
        if (text(status)) { where.append(" AND upper(COALESCE(f.status,''))=upper(?)"); args.add(status); }
        if (text(target)) { where.append(" AND lower(f.target_host || ':' || f.target_port)=lower(?)"); args.add(target); }
        Cursor c = decode(cursor);
        if (c != null) { where.append(" AND (f.last_seen,f.finding_id) < (?,?)"); args.add(Timestamp.from(Instant.parse(c.value()))); args.add(c.id()); }
        args.add(bounded + 1);
        List<FindingItem> rows = jdbc.query("""
                SELECT f.finding_id,f.agent_id,a.display_name,f.target_host,f.target_port,f.trust_verdict,
                       f.performance_verdict,f.occurrence_count,f.status,f.first_seen,f.last_seen,m.incident_id,
                       f.changes::text AS changes
                FROM findings f JOIN agents a ON a.agent_id=f.agent_id
                LEFT JOIN incident_findings m ON m.finding_id=f.finding_id
                """ + where + " ORDER BY f.last_seen DESC,f.finding_id DESC LIMIT ?",
                (rs,n) -> findingItem(rs.getString("finding_id"), rs.getString("agent_id"), rs.getString("display_name"),
                        rs.getString("target_host"), rs.getInt("target_port"), rs.getString("trust_verdict"), rs.getString("performance_verdict"),
                        rs.getLong("occurrence_count"), rs.getString("status"), instant(rs.getTimestamp("first_seen")),
                        instant(rs.getTimestamp("last_seen")), rs.getString("incident_id"), rs.getString("changes")),
                args.toArray());
        return page(rows, bounded, r -> encode(r.lastSeen().toString(), r.id()));
    }

    @GetMapping("/findings/{findingId}")
    public FindingItem finding(@PathVariable String findingId) {
        List<FindingItem> rows = jdbc.query("""
                SELECT f.finding_id,f.agent_id,a.display_name,f.target_host,f.target_port,f.trust_verdict,
                       f.performance_verdict,f.occurrence_count,f.status,f.first_seen,f.last_seen,m.incident_id,
                       f.changes::text AS changes
                FROM findings f JOIN agents a ON a.agent_id=f.agent_id
                LEFT JOIN incident_findings m ON m.finding_id=f.finding_id WHERE f.finding_id=?
                """, (rs,n) -> findingItem(rs.getString("finding_id"),rs.getString("agent_id"),rs.getString("display_name"),
                        rs.getString("target_host"),rs.getInt("target_port"),rs.getString("trust_verdict"),rs.getString("performance_verdict"),
                        rs.getLong("occurrence_count"),rs.getString("status"),instant(rs.getTimestamp("first_seen")),
                        instant(rs.getTimestamp("last_seen")),rs.getString("incident_id"),rs.getString("changes")), findingId);
        if(rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"finding not found");
        return rows.getFirst();
    }

    @GetMapping("/certificates")
    public Page<CertificateItem> certificates(@RequestParam(defaultValue="50") int limit,
                                              @RequestParam(required=false) String cursor,
                                              @RequestParam(required=false) String state,
                                              @RequestParam(required=false) String search) {
        int bounded=bounded(limit); List<Object> args=new ArrayList<>(); StringBuilder where=new StringBuilder(" WHERE 1=1");
        if(text(search)){where.append(" AND (lower(agent_id) LIKE lower(?) OR lower(COALESCE(display_name,'')) LIKE lower(?))");args.add("%"+search+"%");args.add("%"+search+"%");}
        Cursor c=decode(cursor); if(c!=null){where.append(" AND (lower(COALESCE(NULLIF(display_name,''),agent_id)),agent_id)>(?,?)");args.add(c.value());args.add(c.id());}
        args.add(bounded+1);
        List<CertificateItem> rows=jdbc.query("""
                SELECT agent_id,display_name,status,certificate_sha256,certificate_not_before,certificate_not_after,certificate_rotated_at,
                       CASE WHEN certificate_not_after IS NULL THEN 'UNKNOWN'
                            WHEN certificate_not_after <= now() THEN 'EXPIRED'
                            WHEN certificate_not_after <= now()+interval '7 days' THEN 'CRITICAL'
                            WHEN certificate_not_after <= now()+interval '30 days' THEN 'EXPIRING'
                            ELSE 'VALID' END lifecycle
                FROM agents
                """+where+(text(state)?" AND upper(CASE WHEN certificate_not_after IS NULL THEN 'UNKNOWN' WHEN certificate_not_after <= now() THEN 'EXPIRED' WHEN certificate_not_after <= now()+interval '7 days' THEN 'CRITICAL' WHEN certificate_not_after <= now()+interval '30 days' THEN 'EXPIRING' ELSE 'VALID' END)=upper(?)":"")+
                " ORDER BY lower(COALESCE(NULLIF(display_name,''),agent_id)),agent_id LIMIT ?",
                (rs,n)->new CertificateItem(rs.getString("agent_id"),display(rs.getString("display_name"),rs.getString("agent_id")),rs.getString("status"),
                        rs.getString("lifecycle"),rs.getString("certificate_sha256"),instant(rs.getTimestamp("certificate_not_before")),instant(rs.getTimestamp("certificate_not_after")),instant(rs.getTimestamp("certificate_rotated_at"))),
                withState(args,state).toArray());
        return page(rows,bounded,r->encode(r.agentName().toLowerCase(Locale.ROOT),r.agentId()));
    }

    @GetMapping("/upgrades")
    public Page<UpgradeItem> upgrades(@RequestParam(defaultValue="50") int limit,
                                      @RequestParam(required=false) String cursor,
                                      @RequestParam(required=false) String agent,
                                      @RequestParam(required=false) String status) {
        int bounded=bounded(limit); List<Object> args=new ArrayList<>(); StringBuilder where=new StringBuilder(" WHERE 1=1");
        if(text(agent)){where.append(" AND agent_id=?");args.add(agent);} if(text(status)){where.append(" AND upper(status)=upper(?)");args.add(status);}
        Cursor c=decode(cursor); if(c!=null){where.append(" AND (requested_at,upgrade_id)<(?,CAST(? AS uuid))");args.add(Timestamp.from(Instant.parse(c.value())));args.add(c.id());}
        args.add(bounded+1);
        List<UpgradeItem> rows=jdbc.query("""
                SELECT upgrade_id,agent_id,from_version,from_build_id,target_version,target_build_id,status,target_os,target_arch,
                       source_type,source_ref,requested_at,failure_code,failure_message FROM agent_upgrades
                """+where+" ORDER BY requested_at DESC,upgrade_id DESC LIMIT ?",
                (rs,n)->new UpgradeItem(rs.getObject("upgrade_id",UUID.class),rs.getString("agent_id"),rs.getString("from_version"),rs.getString("from_build_id"),
                        rs.getString("target_version"),rs.getString("target_build_id"),rs.getString("status"),rs.getString("target_os"),rs.getString("target_arch"),
                        rs.getString("source_type"),rs.getString("source_ref"),instant(rs.getTimestamp("requested_at")),rs.getString("failure_code"),rs.getString("failure_message")),args.toArray());
        return page(rows,bounded,r->encode(r.requestedAt().toString(),r.id().toString()));
    }

    private FindingItem findingItem(String id,String agentId,String displayName,String host,int port,String trust,String performance,long count,String status,Instant firstSeen,Instant lastSeen,String incidentId,String changes) {
        String type = findingAttribute(changes,"Finding type:",fallbackFindingType(id));
        String severity = findingAttribute(changes,"Severity:","-");
        String confidence = formatConfidence(findingAttribute(changes,"Confidence:","-"));
        String intent = findingAttribute(changes,"Malicious intent:","UNKNOWN");
        return new FindingItem(id,agentId,display(displayName,agentId),host,port,
                type,severity,confidence,assessment(type,trust,intent),trust,performance,count,status,firstSeen,lastSeen,incidentId);
    }

    private String findingAttribute(String changes,String prefix,String fallback) {
        if(!text(changes)) return fallback;
        try {
            JsonNode node=mapper.readTree(changes);
            if(node!=null&&node.isArray()) {
                for(JsonNode item:node) {
                    if(item.isTextual()) {
                        String value=item.asText();
                        if(value.regionMatches(true,0,prefix,0,prefix.length())) {
                            String extracted=value.substring(prefix.length()).trim();
                            if(!extracted.isEmpty()) return extracted;
                        }
                    }
                }
            }
        } catch(Exception ignored) { }
        return fallback;
    }

    private static String fallbackFindingType(String id){if(!text(id))return "-";if(id.startsWith("FINDING-BEHAVIOR-"))return "BEHAVIOR";if(id.startsWith("FINDING-TRANSFER-"))return "TRANSFER_BEHAVIOR";return "CONNECTION_ASSURANCE";}
    private static String formatConfidence(String confidence){if(!text(confidence)||"-".equals(confidence))return "-";try{return String.format(Locale.ROOT,"%.2f",Double.parseDouble(confidence));}catch(NumberFormatException ignored){return confidence;}}
    private static String assessment(String findingType,String trust,String maliciousIntent){String type=upper(findingType);if("CONNECTION_ASSURANCE".equals(type)){String peer=upper(trust);return "-".equals(peer)?"PEER_UNKNOWN":"PEER_"+peer;}String intent=upper(maliciousIntent);return "INTENT_"+("-".equals(intent)?"UNKNOWN":intent);}
    private static String upper(String value){return text(value)?value.toUpperCase(Locale.ROOT):"-";}
    private static List<Object> withState(List<Object> args,String state){if(text(state))args.add(args.size()-1,state);return args;}
    private static int bounded(int limit){return Math.max(1,Math.min(MAX_LIMIT,limit));}
    private static boolean text(String value){return value!=null&&!value.isBlank();}
    private static String display(String name,String id){return text(name)?name:id;}
    private static Instant instant(Timestamp value){return value==null?null:value.toInstant();}
    private static String encode(String value,String id){return Base64.getUrlEncoder().withoutPadding().encodeToString((value+"\n"+id).getBytes(StandardCharsets.UTF_8));}
    private static Cursor decode(String raw){if(!text(raw))return null;try{String decoded=new String(Base64.getUrlDecoder().decode(raw),StandardCharsets.UTF_8);int nl=decoded.indexOf('\n');if(nl<=0||nl==decoded.length()-1)throw new IllegalArgumentException();return new Cursor(decoded.substring(0,nl),decoded.substring(nl+1));}catch(RuntimeException e){throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"invalid cursor");}}
    private static <T> Page<T> page(List<T> rows,int limit,java.util.function.Function<T,String> cursorFn){boolean more=rows.size()>limit;List<T> items=more?List.copyOf(rows.subList(0,limit)):List.copyOf(rows);String next=more&&!items.isEmpty()?cursorFn.apply(items.getLast()):null;return new Page<>(items,next);}

    public record Page<T>(List<T> items,String nextCursor){}
    private record Cursor(String value,String id){}
    private record AgentCounts(long total,long online,long linux,long windows){}
    public record FleetAgents(long total,long online,long offline,long linux,long windows){}
    public record FindingCounts(long total,long active,long suspicious,long changed){}
    public record CertificateCounts(long valid,long expiring,long critical,long expired,long unknown){}
    public record FleetSummary(FleetAgents agents,FindingCounts findings,CertificateCounts certificates){}
    public record AgentItem(String id,String name,String state,Instant lastSeen,String version,String build,String gitCommit,String os,String arch,String artifactSha256,Integer protocolVersion,Integer schemaVersion,String features,String certificateSha256,Instant enrolledAt,long lastSequence){}
    public record FindingItem(String id,String agentId,String agentName,String host,int port,String type,String severity,String confidence,String assessment,String trust,String performance,long count,String status,Instant firstSeen,Instant lastSeen,String incidentId){}
    public record CertificateItem(String agentId,String agentName,String agentStatus,String state,String fingerprint,Instant notBefore,Instant notAfter,Instant rotatedAt){}
    public record UpgradeItem(UUID id,String agentId,String fromVersion,String fromBuild,String targetVersion,String targetBuild,String status,String os,String arch,String sourceType,String sourceRef,Instant requestedAt,String failureCode,String failureMessage){}
}
