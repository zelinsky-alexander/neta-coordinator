package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.finding.FindingQueryService;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
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
    private final FindingQueryService findingQueries;

    public FindingInvestigationController(JdbcTemplate jdbc, ObjectMapper mapper,
                                          FindingQueryService findingQueries) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.findingQueries = findingQueries;
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
        Long newerThanSeconds = text(since) ? FindingQueryService.parseAge(since).toSeconds() : null;
        FindingQueryService.Page page = findingQueries.search(
                new FindingQueryService.Filter(agent, trust, performance, status, target, null, null,
                        null, null, newerThanSeconds),
                new FindingQueryService.PageRequest(boundedLimit, Math.max(0, offset), sort,
                        "asc".equalsIgnoreCase(order), null, null));
        List<FindingQueryService.Finding> rows = page.items();

        StringBuilder out = new StringBuilder();
        out.append("Findings matched: ").append(page.matched())
                .append("  showing: ").append(rows.size())
                .append("  offset: ").append(Math.max(0, offset)).append("\n\n");
        out.append(String.format("%-25s %-20s %-27s %-32s %-9s %-10s %-20s %5s %-8s %-20s %-20s %s%n",
                "LAST SEEN","AGENT","SUBJECT","TYPE","SEVERITY","CONFIDENCE","ASSESSMENT","COUNT","STATUS","POPULATION","INCIDENT","FINDING"));
        out.append("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
        for (FindingQueryService.Finding r : rows) {
            out.append(String.format("%-25s %-20s %-27s %-32s %-9s %-10s %-20s %5d %-8s %-20s %-20s %s%n",
                    r.lastSeen() == null ? "-" : r.lastSeen().toString(), trim(r.agentName(),20), trim(r.subject(),27),
                    trim(value(r.type()),32), value(r.severity()), r.confidence(), trim(r.assessment(),20),
                    r.count(), value(r.status()), r.population(), r.incidentId()==null?"-":r.incidentId(), r.id()));
        }
        return out.toString();
    }

    @GetMapping(value = "/finding-summary", produces = MediaType.TEXT_PLAIN_VALUE)
    public String summary() {
        FindingQueryService.Summary summary = findingQueries.summary();
        StringBuilder out = new StringBuilder("Findings\n================================\n");
        metric(out,"Retained",summary.retained());
        metric(out,"Current actionable",summary.currentActionable());
        metric(out,"Active historical",summary.activeHistorical());
        metric(out,"Recent candidates",summary.recentCandidates());
        out.append("\nSeverity\n");
        metric(out,"Critical",summary.critical()); metric(out,"High",summary.high());
        metric(out,"Medium",summary.medium()); metric(out,"Low",summary.low());
        out.append("\nOldest active: ").append(age(summary.oldestActive(), Instant.now())).append('\n');
        return out.toString();
    }

    @GetMapping(value = "/finding-detail", produces = MediaType.TEXT_PLAIN_VALUE)
    public String detail(@RequestParam("id") String id) {
        List<Detail> rows = jdbc.query("""
                SELECT f.finding_id,f.finding_key,f.message_id,f.agent_id,a.display_name,
                       f.target_host,f.target_port,f.subject_type,f.subject_id,f.severity,f.rule_id,
                       f.performance_verdict,f.trust_verdict,f.status,
                       f.occurrence_count,f.first_seen,f.last_seen,f.observed_from,f.observed_to,
                       f.evidence_root,f.changes::text,f.rule_set::text,f.payload::text,m.incident_id
                FROM findings f JOIN agents a ON a.agent_id=f.agent_id
                LEFT JOIN incident_findings m ON m.finding_id=f.finding_id
                WHERE f.finding_id=?
                """, (rs,n) -> new Detail(rs.getString("finding_id"),rs.getString("finding_key"),rs.getString("message_id"),
                        rs.getString("agent_id"),rs.getString("display_name"),rs.getString("target_host"),rs.getObject("target_port", Integer.class),
                        rs.getString("subject_type"),rs.getString("subject_id"),rs.getString("severity"),rs.getString("rule_id"),
                        rs.getString("performance_verdict"),rs.getString("trust_verdict"),rs.getString("status"),rs.getLong("occurrence_count"),
                        instant(rs.getTimestamp("first_seen")),instant(rs.getTimestamp("last_seen")),instant(rs.getTimestamp("observed_from")),
                        instant(rs.getTimestamp("observed_to")),rs.getString("evidence_root"),rs.getString("changes"),rs.getString("rule_set"),
                        rs.getString("payload"),rs.getString("incident_id")), id);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"finding not found");
        Detail r = rows.getFirst();
        Instant now = Instant.now();
        boolean process = "PROCESS".equalsIgnoreCase(r.subjectType());
        String subject = process ? processSubjectDisplay(r.changes(), r.subjectId()) : networkSubject(r.host(), r.port());
        String findingType = process && text(r.ruleId()) ? r.ruleId() : fallbackFindingType(r.findingId());
        StringBuilder out = new StringBuilder();
        out.append(r.findingId()).append("\n\n");
        line(out,"Agent",display(r.displayName(),r.agentId())+" ("+r.agentId()+")");
        line(out,"Incident",r.incidentId()==null?"-":r.incidentId());
        line(out,"Subject",subject);
        if (process) {
            line(out,"Subject type",value(r.subjectType()));
            line(out,"Subject ID",raw(r.subjectId()));
            line(out,"Rule ID",raw(r.ruleId()));
            line(out,"Severity",value(r.severity()));
            line(out,"Assessment","BEHAVIORAL_PATTERN");
        }
        line(out,"Type",value(findingType));
        line(out,"State",value(r.status()));
        line(out,"Occurrences",Long.toString(r.count()));
        line(out,"First seen",age(r.firstSeen(),now)+" ("+r.firstSeen()+")");
        line(out,"Last seen",age(r.lastSeen(),now)+" ("+r.lastSeen()+")");
        out.append("\nAssessment\n----------\n");
        if (!process) {
            line(out,"Trust",value(r.trust()));
            line(out,"Performance",value(r.performance()));
        } else {
            line(out,"Interpretation",findingAttribute(r.changes(),"Interpretation:","Behavioral pattern observed; malicious intent is not established."));
        }
        out.append("\nObserved changes\n----------------\n").append(pretty(r.changes())).append('\n');
        out.append("\nEvidence\n--------\n");
        line(out,"Evidence root",raw(r.evidenceRoot())); line(out,"Finding key",raw(r.findingKey())); line(out,"Message ID",raw(r.messageId()));
        line(out,"Observed from",r.observedFrom()==null?"-":r.observedFrom().toString());
        line(out,"Observed to",r.observedTo()==null?"-":r.observedTo().toString());
        out.append("\nRule set\n--------\n").append(pretty(r.ruleSet())).append('\n');
        out.append("\nRaw payload\n-----------\n").append(pretty(r.payload())).append('\n');
        return out.toString();
    }

    private String findingAttribute(String changes, String prefix, String fallback) {
        if (!text(changes)) return fallback;
        try {
            JsonNode node = mapper.readTree(changes);
            if (node != null && node.isArray()) {
                for (JsonNode item : node) {
                    if (item.isTextual()) {
                        String value = item.asText();
                        if (value.regionMatches(true, 0, prefix, 0, prefix.length())) {
                            String extracted = value.substring(prefix.length()).trim();
                            if (!extracted.isEmpty()) return extracted;
                        }
                    }
                }
            }
        } catch (Exception ignored) { }
        return fallback;
    }

    private String processSubjectDisplay(String changes,String subjectId) {
        String image=findingAttribute(changes,"Process image:","");
        if(text(image)) {
            String normalized=image.replace('\\','/');
            int slash=normalized.lastIndexOf('/');
            String leaf=slash>=0?normalized.substring(slash+1):normalized;
            if(text(leaf)) return leaf;
        }
        return text(subjectId)?subjectId:"process";
    }

    private static String networkSubject(String host,Integer port) {
        if(!text(host)) return "-";
        return port==null?host:host+":"+port;
    }

    private static String fallbackFindingType(String findingId) {
        if (!text(findingId)) return "-";
        if (findingId.startsWith("FINDING-BEHAVIOR-")) return "BEHAVIOR";
        if (findingId.startsWith("FINDING-TRANSFER-")) return "TRANSFER_BEHAVIOR";
        return "CONNECTION_ASSURANCE";
    }

    private static String formatConfidence(String confidence) {
        if (!text(confidence) || "-".equals(confidence)) return "-";
        try { return String.format(Locale.ROOT, "%.2f", Double.parseDouble(confidence)); }
        catch (NumberFormatException ignored) { return confidence; }
    }

    private static String assessment(String findingType, String trust, String maliciousIntent) {
        String type = value(findingType);
        if ("CONNECTION_ASSURANCE".equals(type)) {
            String peer = value(trust);
            return "-".equals(peer) ? "PEER_UNKNOWN" : "PEER_" + peer;
        }
        String intent = value(maliciousIntent);
        return "INTENT_" + ("-".equals(intent) ? "UNKNOWN" : intent);
    }

    private String pretty(String json) {
        if (!text(json)) return "{}";
        try { JsonNode node=mapper.readTree(json); return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(node); }
        catch (Exception e) { return json; }
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

    private record Detail(String findingId,String findingKey,String messageId,String agentId,String displayName,String host,Integer port,String subjectType,String subjectId,String severity,String ruleId,String performance,String trust,String status,long count,Instant firstSeen,Instant lastSeen,Instant observedFrom,Instant observedTo,String evidenceRoot,String changes,String ruleSet,String payload,String incidentId){}
}
