package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/operator")
public class FindingInvestigationController {
    private static final int MAX_LIMIT = 100;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public FindingInvestigationController(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @GetMapping(value = "/finding-search", produces = MediaType.TEXT_PLAIN_VALUE)
    public String search(
            @RequestParam(required = false) String agent,
            @RequestParam(required = false) String trust,
            @RequestParam(required = false) String performance,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String target,
            @RequestParam(required = false) String since,
            @RequestParam(defaultValue = "last_seen") String sort,
            @RequestParam(defaultValue = "desc") String order,
            @RequestParam(defaultValue = "10") int limit,
            @RequestParam(defaultValue = "0") int offset) {

        int boundedLimit = Math.max(1, Math.min(limit, MAX_LIMIT));
        int boundedOffset = Math.max(0, offset);
        List<Object> args = new ArrayList<>();
        StringBuilder where = new StringBuilder(" WHERE 1=1");

        if (text(agent)) {
            where.append(" AND (f.agent_id=? OR lower(COALESCE(a.display_name,''))=lower(?))");
            args.add(agent); args.add(agent);
        }
        if (text(trust)) {
            where.append(" AND upper(COALESCE(f.trust_verdict,''))=upper(?)");
            args.add(trust);
        }
        if (text(performance)) {
            where.append(" AND upper(COALESCE(f.performance_verdict,''))=upper(?)");
            args.add(performance);
        }
        if (text(status)) {
            where.append(" AND upper(COALESCE(f.status,''))=upper(?)");
            args.add(status);
        }
        if (text(target)) {
            Target parsed = parseTarget(target);
            where.append(" AND lower(f.target_host)=lower(?)");
            args.add(parsed.host());
            if (parsed.port() != null) {
                where.append(" AND f.target_port=?");
                args.add(parsed.port());
            }
        }
        if (text(since)) {
            where.append(" AND f.last_seen>=?");
            args.add(Timestamp.from(Instant.now().minus(parseAge(since))));
        }

        String sortColumn = switch (sort.toLowerCase(Locale.ROOT)) {
            case "first_seen" -> "f.first_seen";
            case "occurrences", "count" -> "f.occurrence_count";
            case "agent" -> "COALESCE(NULLIF(a.display_name,''),f.agent_id)";
            case "target" -> "f.target_host";
            default -> "f.last_seen";
        };
        String direction = "asc".equalsIgnoreCase(order) ? "ASC" : "DESC";

        String from = " FROM findings f JOIN agents a ON a.agent_id=f.agent_id " +
                "LEFT JOIN incident_findings m ON m.finding_id=f.finding_id";
        Long matched = jdbc.queryForObject("SELECT count(*)" + from + where, Long.class, args.toArray());

        List<Object> rowArgs = new ArrayList<>(args);
        rowArgs.add(boundedLimit);
        rowArgs.add(boundedOffset);
        List<Row> rows = jdbc.query("""
                SELECT f.finding_id,f.agent_id,a.display_name,f.target_host,f.target_port,
                       f.trust_verdict,f.performance_verdict,f.occurrence_count,f.status,
                       f.first_seen,f.last_seen,m.incident_id
                """ + from + where + " ORDER BY " + sortColumn + " " + direction + ", f.finding_id LIMIT ? OFFSET ?",
                (rs, n) -> new Row(rs.getString("finding_id"), rs.getString("agent_id"), rs.getString("display_name"),
                        rs.getString("target_host"), rs.getInt("target_port"), rs.getString("trust_verdict"),
                        rs.getString("performance_verdict"), rs.getLong("occurrence_count"), rs.getString("status"),
                        instant(rs.getTimestamp("first_seen")), instant(rs.getTimestamp("last_seen")), rs.getString("incident_id")),
                rowArgs.toArray());

        StringBuilder out = new StringBuilder();
        out.append("Findings matched: ").append(matched == null ? 0 : matched)
                .append("  showing: ").append(rows.size())
                .append("  offset: ").append(boundedOffset).append("\n\n");
        out.append(String.format("%-10s %-20s %-27s %-13s %-21s %5s %-8s %-20s %s%n",
                "LAST SEEN","AGENT","TARGET","TRUST","PERFORMANCE","COUNT","STATUS","INCIDENT","FINDING"));
        out.append("------------------------------------------------------------------------------------------------------------------------------------------------\n");
        Instant now = Instant.now();
        for (Row r : rows) {
            out.append(String.format("%-10s %-20s %-27s %-13s %-21s %5d %-8s %-20s %s%n",
                    age(r.lastSeen(), now), trim(display(r.displayName(), r.agentId()),20),
                    trim(r.host()+":"+r.port(),27), value(r.trust()), value(r.performance()), r.count(), value(r.status()),
                    r.incidentId()==null?"-":r.incidentId(), r.findingId()));
        }
        return out.toString();
    }

    @GetMapping(value = "/finding-summary", produces = MediaType.TEXT_PLAIN_VALUE)
    public String summary() {
        Aggregate agg = jdbc.queryForObject("""
                SELECT count(*) total,
                       count(*) FILTER (WHERE status='ACTIVE') active,
                       count(*) FILTER (WHERE upper(COALESCE(trust_verdict,''))='STABLE') stable,
                       count(*) FILTER (WHERE upper(COALESCE(trust_verdict,''))='CHANGED') changed,
                       count(*) FILTER (WHERE upper(COALESCE(trust_verdict,''))='SUSPICIOUS') suspicious
                FROM findings
                """, (rs,n) -> new Aggregate(rs.getLong("total"),rs.getLong("active"),rs.getLong("stable"),rs.getLong("changed"),rs.getLong("suspicious")));
        List<CountRow> performance = jdbc.query("""
                SELECT COALESCE(NULLIF(upper(performance_verdict),''),'-') label, count(*) n
                FROM findings GROUP BY 1 ORDER BY n DESC, label LIMIT 8
                """, (rs,n) -> new CountRow(rs.getString("label"),rs.getLong("n")));
        List<CountRow> targets = jdbc.query("""
                SELECT target_host || ':' || target_port AS label, count(*) n
                FROM findings GROUP BY target_host,target_port ORDER BY n DESC,label LIMIT 5
                """, (rs,n) -> new CountRow(rs.getString("label"),rs.getLong("n")));
        List<CountRow> agents = jdbc.query("""
                SELECT COALESCE(NULLIF(a.display_name,''),f.agent_id) label, count(*) n
                FROM findings f JOIN agents a ON a.agent_id=f.agent_id
                GROUP BY 1 ORDER BY n DESC,label LIMIT 5
                """, (rs,n) -> new CountRow(rs.getString("label"),rs.getLong("n")));

        if (agg == null) agg = new Aggregate(0,0,0,0,0);
        StringBuilder out = new StringBuilder("Findings\n================================\n");
        metric(out,"Total",agg.total()); metric(out,"Active",agg.active());
        out.append("\nTrust\n"); metric(out,"Stable",agg.stable()); metric(out,"Changed",agg.changed()); metric(out,"Suspicious",agg.suspicious());
        out.append("\nPerformance\n"); for (CountRow r: performance) metric(out,r.label(),r.count());
        out.append("\nTop targets\n"); for (CountRow r: targets) metric(out,r.label(),r.count());
        out.append("\nMost active endpoints\n"); for (CountRow r: agents) metric(out,r.label(),r.count());
        return out.toString();
    }

    @GetMapping(value = "/finding-detail", produces = MediaType.TEXT_PLAIN_VALUE)
    public String detail(@RequestParam("id") String id) {
        List<Detail> rows = jdbc.query("""
                SELECT f.finding_id,f.finding_key,f.message_id,f.agent_id,a.display_name,
                       f.target_host,f.target_port,f.performance_verdict,f.trust_verdict,f.status,
                       f.occurrence_count,f.first_seen,f.last_seen,f.observed_from,f.observed_to,
                       f.evidence_root,f.changes::text,f.rule_set::text,f.payload::text,m.incident_id
                FROM findings f JOIN agents a ON a.agent_id=f.agent_id
                LEFT JOIN incident_findings m ON m.finding_id=f.finding_id
                WHERE f.finding_id=?
                """, (rs,n) -> new Detail(rs.getString("finding_id"),rs.getString("finding_key"),rs.getString("message_id"),
                        rs.getString("agent_id"),rs.getString("display_name"),rs.getString("target_host"),rs.getInt("target_port"),
                        rs.getString("performance_verdict"),rs.getString("trust_verdict"),rs.getString("status"),rs.getLong("occurrence_count"),
                        instant(rs.getTimestamp("first_seen")),instant(rs.getTimestamp("last_seen")),instant(rs.getTimestamp("observed_from")),
                        instant(rs.getTimestamp("observed_to")),rs.getString("evidence_root"),rs.getString("changes"),rs.getString("rule_set"),
                        rs.getString("payload"),rs.getString("incident_id")), id);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"finding not found");
        Detail r = rows.getFirst();
        Instant now = Instant.now();
        StringBuilder out = new StringBuilder();
        out.append(r.findingId()).append("\n\n");
        line(out,"Agent",display(r.displayName(),r.agentId())+" ("+r.agentId()+")");
        line(out,"Incident",r.incidentId()==null?"-":r.incidentId());
        line(out,"Target",r.host()+":"+r.port());
        line(out,"State",value(r.status()));
        line(out,"Occurrences",Long.toString(r.count()));
        line(out,"First seen",age(r.firstSeen(),now)+" ("+r.firstSeen()+")");
        line(out,"Last seen",age(r.lastSeen(),now)+" ("+r.lastSeen()+")");
        out.append("\nAssessment\n----------\n");
        line(out,"Trust",value(r.trust())); line(out,"Performance",value(r.performance()));
        out.append("\nObserved changes\n----------------\n").append(pretty(r.changes())).append('\n');
        out.append("\nEvidence\n--------\n");
        line(out,"Evidence root",raw(r.evidenceRoot())); line(out,"Finding key",raw(r.findingKey())); line(out,"Message ID",raw(r.messageId()));
        line(out,"Observed from",r.observedFrom()==null?"-":r.observedFrom().toString());
        line(out,"Observed to",r.observedTo()==null?"-":r.observedTo().toString());
        out.append("\nRule set\n--------\n").append(pretty(r.ruleSet())).append('\n');
        out.append("\nRaw payload\n-----------\n").append(pretty(r.payload())).append('\n');
        return out.toString();
    }

    private String pretty(String json) {
        if (!text(json)) return "{}";
        try { JsonNode node=mapper.readTree(json); return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(node); }
        catch (Exception e) { return json; }
    }
    private static Duration parseAge(String raw) {
        String s=raw.trim().toLowerCase(Locale.ROOT);
        try {
            if (s.matches("[0-9]+[smhd]")) {
                long n=Long.parseLong(s.substring(0,s.length()-1));
                return switch(s.charAt(s.length()-1)) { case 's' -> Duration.ofSeconds(n); case 'm' -> Duration.ofMinutes(n); case 'h' -> Duration.ofHours(n); default -> Duration.ofDays(n); };
            }
            return Duration.parse(raw.toUpperCase(Locale.ROOT));
        } catch (RuntimeException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"invalid --since duration; use 30m, 24h, 7d or ISO-8601 PT24H"); }
    }
    private static Target parseTarget(String raw) {
        int colon=raw.lastIndexOf(':');
        if (colon>0 && colon<raw.length()-1) {
            try { int p=Integer.parseInt(raw.substring(colon+1)); if (p<1||p>65535) throw new NumberFormatException(); return new Target(raw.substring(0,colon),p); }
            catch(NumberFormatException ignored) { }
        }
        return new Target(raw,null);
    }
    private static void metric(StringBuilder out,String label,long n){ out.append(String.format("  %-24s %d%n",label,n)); }
    private static void line(StringBuilder out,String label,String v){ out.append(String.format("%-18s %s%n",label+":",raw(v))); }
    private static boolean text(String s){ return s!=null&&!s.isBlank(); }
    private static String value(String s){ return text(s)?s.toUpperCase(Locale.ROOT):"-"; }
    private static String raw(String s){ return text(s)?s:"-"; }
    private static String display(String name,String id){ return text(name)?name:id; }
    private static String trim(String s,int width){ return s.length()<=width?s:s.substring(0,width-1)+"…"; }
    private static Instant instant(Timestamp ts){ return ts==null?null:ts.toInstant(); }
    private static String age(Instant then,Instant now){ if(then==null)return "never"; long sec=Math.max(0,Duration.between(then,now).getSeconds()); if(sec<60)return sec+" sec"; long min=sec/60; if(min<60)return min+" min"; long h=min/60; if(h<48)return h+" hr"; return h/24+" day"; }

    private record Target(String host,Integer port){}
    private record Row(String findingId,String agentId,String displayName,String host,int port,String trust,String performance,long count,String status,Instant firstSeen,Instant lastSeen,String incidentId){}
    private record Detail(String findingId,String findingKey,String messageId,String agentId,String displayName,String host,int port,String performance,String trust,String status,long count,Instant firstSeen,Instant lastSeen,Instant observedFrom,Instant observedTo,String evidenceRoot,String changes,String ruleSet,String payload,String incidentId){}
    private record Aggregate(long total,long active,long stable,long changed,long suspicious){}
    private record CountRow(String label,long count){}
}
