package dev.neta.coordinator.finding;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Coordinator-owned finding selection, lifecycle populations, ordering and aggregation. */
@Service
public class FindingQueryService {
    public static final int MAX_LIMIT = 100;
    public static final long MAX_AGE_SECONDS = 10L * 365 * 24 * 60 * 60;

    private static final String ASSESSMENT_SQL = """
            CASE
              WHEN upper(COALESCE(f.subject_type,''))='PROCESS' THEN 'BEHAVIORAL_PATTERN'
              WHEN upper(COALESCE(NULLIF(f.rule_id,''),
                   (SELECT trim(substr(entry,length('Finding type:')+1))
                      FROM jsonb_array_elements_text(COALESCE(f.changes,'[]'::jsonb)) entry
                     WHERE lower(entry) LIKE 'finding type:%' LIMIT 1),
                   CASE WHEN f.finding_id LIKE 'FINDING-BEHAVIOR-%' THEN 'BEHAVIOR'
                        WHEN f.finding_id LIKE 'FINDING-TRANSFER-%' THEN 'TRANSFER_BEHAVIOR'
                        ELSE 'CONNECTION_ASSURANCE' END))='CONNECTION_ASSURANCE'
                THEN 'PEER_' || COALESCE(NULLIF(upper(f.trust_verdict),''),'UNKNOWN')
              ELSE 'INTENT_' || COALESCE(NULLIF(upper(
                   (SELECT trim(substr(entry,length('Malicious intent:')+1))
                      FROM jsonb_array_elements_text(COALESCE(f.changes,'[]'::jsonb)) entry
                     WHERE lower(entry) LIKE 'malicious intent:%' LIMIT 1)),''),'UNKNOWN')
            END
            """;
    private static final String FROM_SQL = """
             FROM findings f JOIN agents a ON a.agent_id=f.agent_id
             LEFT JOIN incident_findings m ON m.finding_id=f.finding_id
            """;
    private static final String SELECT_SQL = """
            SELECT f.finding_id,f.agent_id,a.display_name,f.target_host,f.target_port,
                   f.subject_type,f.subject_id,f.severity,f.rule_id,f.trust_verdict,
                   f.performance_verdict,f.occurrence_count,f.status,f.first_seen,f.last_seen,
                   m.incident_id,f.changes::text AS changes,f.observed_from,f.observed_to,
                   f.evidence_root,f.rule_set::text AS rule_set
            """;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final Duration currentActionableWindow;
    private final Duration recentCandidateWindow;
    private final Clock clock;

    public FindingQueryService(JdbcTemplate jdbc, ObjectMapper mapper,
                               @Value("${NETA_FINDINGS_CURRENT_ACTIONABLE_WINDOW:PT24H}") Duration currentActionableWindow,
                               @Value("${NETA_FINDINGS_RECENT_CANDIDATE_WINDOW:PT1H}") Duration recentCandidateWindow) {
        this(jdbc, mapper, currentActionableWindow, recentCandidateWindow, Clock.systemUTC());
    }

    FindingQueryService(JdbcTemplate jdbc, ObjectMapper mapper, Duration currentActionableWindow,
                        Duration recentCandidateWindow, Clock clock) {
        if (currentActionableWindow.isZero() || currentActionableWindow.isNegative()
                || recentCandidateWindow.isZero() || recentCandidateWindow.isNegative()) {
            throw new IllegalArgumentException("finding population windows must be positive");
        }
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.currentActionableWindow = currentActionableWindow;
        this.recentCandidateWindow = recentCandidateWindow;
        this.clock = clock;
    }

    public Page search(Filter filter, PageRequest request) {
        Filter normalized = filter == null ? Filter.defaults() : filter;
        validateAge(normalized.olderThanSeconds(), normalized.newerThanSeconds());
        int limit = Math.max(1, Math.min(request.limit(), MAX_LIMIT));
        int offset = Math.max(0, request.offset());
        BuiltFilter built = build(normalized, request.cursorLastSeen(), request.cursorId(), clock.instant());
        Long matched = jdbc.queryForObject("SELECT count(*)" + FROM_SQL + built.where(),
                Long.class, built.args().toArray());
        List<Object> args = new ArrayList<>(built.args());
        args.add(limit + 1);
        args.add(offset);
        String order = orderBy(request.sort(), request.ascending());
        List<Finding> rows = jdbc.query(SELECT_SQL + FROM_SQL + built.where()
                        + " ORDER BY " + order + " LIMIT ? OFFSET ?",
                (rs, ignored) -> map(rs), args.toArray());
        boolean more = rows.size() > limit;
        List<Finding> items = more ? List.copyOf(rows.subList(0, limit)) : List.copyOf(rows);
        return new Page(items, matched == null ? 0 : matched, more);
    }

    public Summary summary() {
        Instant now = clock.instant();
        Timestamp currentCutoff = Timestamp.from(now.minus(currentActionableWindow));
        Timestamp candidateCutoff = Timestamp.from(now.minus(recentCandidateWindow));
        Summary result = jdbc.queryForObject("""
                SELECT count(*) retained,
                       count(*) FILTER (WHERE upper(COALESCE(status,''))='ACTIVE' AND last_seen>=?) current_actionable,
                       count(*) FILTER (WHERE upper(COALESCE(status,''))='ACTIVE' AND last_seen<?) active_historical,
                       count(*) FILTER (WHERE upper(COALESCE(status,''))='CANDIDATE' AND last_seen>=?) recent_candidates,
                       min(last_seen) FILTER (WHERE upper(COALESCE(status,''))='ACTIVE') oldest_active,
                       count(*) FILTER (WHERE upper(COALESCE(status,''))='ACTIVE' AND last_seen>=? AND upper(COALESCE(severity,''))='CRITICAL') critical,
                       count(*) FILTER (WHERE upper(COALESCE(status,''))='ACTIVE' AND last_seen>=? AND upper(COALESCE(severity,''))='HIGH') high,
                       count(*) FILTER (WHERE upper(COALESCE(status,''))='ACTIVE' AND last_seen>=? AND upper(COALESCE(severity,''))='MEDIUM') medium,
                       count(*) FILTER (WHERE upper(COALESCE(status,''))='ACTIVE' AND last_seen>=? AND upper(COALESCE(severity,''))='LOW') low
                FROM findings
                """, (rs, ignored) -> new Summary(
                        rs.getLong("retained"), rs.getLong("current_actionable"),
                        rs.getLong("active_historical"), rs.getLong("recent_candidates"),
                        instant(rs.getTimestamp("oldest_active")), rs.getLong("critical"),
                        rs.getLong("high"), rs.getLong("medium"), rs.getLong("low")),
                currentCutoff, currentCutoff, candidateCutoff,
                currentCutoff, currentCutoff, currentCutoff, currentCutoff);
        return result == null ? new Summary(0, 0, 0, 0, null, 0, 0, 0, 0) : result;
    }

    public Selection selection(Filter filter) {
        Filter normalized = filter == null ? Filter.defaults() : filter;
        validateAge(normalized.olderThanSeconds(), normalized.newerThanSeconds());
        BuiltFilter built = build(normalized, null, null, clock.instant());
        return new Selection(built.where(), built.args());
    }

    private BuiltFilter build(Filter filter, Instant cursorLastSeen, String cursorId, Instant now) {
        List<Object> args = new ArrayList<>();
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (text(filter.agent())) {
            where.append(" AND (f.agent_id=? OR lower(COALESCE(a.display_name,''))=lower(?))");
            args.add(filter.agent().trim()); args.add(filter.agent().trim());
        }
        equal(where, args, "f.trust_verdict", filter.trust());
        equal(where, args, "f.performance_verdict", filter.performance());
        equal(where, args, "f.severity", filter.severity());
        equal(where, args, "f.rule_id", filter.rule());
        if (text(filter.assessment())) {
            where.append(" AND upper((").append(ASSESSMENT_SQL).append("))=upper(?)");
            args.add(filter.assessment().trim());
        }
        applyPopulation(where, args, filter.population(), now);
        if (text(filter.target())) {
            Target target = parseTarget(filter.target());
            where.append(" AND lower(COALESCE(f.target_host,''))=lower(?)"); args.add(target.host());
            if (target.port() != null) { where.append(" AND f.target_port=?"); args.add(target.port()); }
        }
        if (filter.olderThanSeconds() != null) {
            where.append(" AND f.last_seen<?"); args.add(Timestamp.from(now.minusSeconds(filter.olderThanSeconds())));
        }
        if (filter.newerThanSeconds() != null) {
            where.append(" AND f.last_seen>=?"); args.add(Timestamp.from(now.minusSeconds(filter.newerThanSeconds())));
        }
        if (cursorLastSeen != null && text(cursorId)) {
            where.append(" AND (f.last_seen,f.finding_id)<(?,?)");
            args.add(Timestamp.from(cursorLastSeen)); args.add(cursorId);
        }
        return new BuiltFilter(where.toString(), List.copyOf(args));
    }

    private void applyPopulation(StringBuilder where, List<Object> args, String raw, Instant now) {
        String population = text(raw) ? raw.trim().toUpperCase(Locale.ROOT) : "CURRENT_ACTIONABLE";
        switch (population) {
            case "CURRENT", "CURRENT_ACTIONABLE" -> {
                where.append(" AND upper(COALESCE(f.status,''))='ACTIVE' AND f.last_seen>=?");
                args.add(Timestamp.from(now.minus(currentActionableWindow)));
            }
            case "ACTIVE_HISTORICAL", "HISTORICAL" -> {
                where.append(" AND upper(COALESCE(f.status,''))='ACTIVE' AND f.last_seen<?");
                args.add(Timestamp.from(now.minus(currentActionableWindow)));
            }
            case "RECENT_CANDIDATES" -> {
                where.append(" AND upper(COALESCE(f.status,''))='CANDIDATE' AND f.last_seen>=?");
                args.add(Timestamp.from(now.minus(recentCandidateWindow)));
            }
            case "ALL", "ANY" -> { }
            default -> { where.append(" AND upper(COALESCE(f.status,''))=?"); args.add(population); }
        }
    }

    private Finding map(ResultSet rs) throws SQLException {
        String changes = rs.getString("changes");
        String subjectType = rs.getString("subject_type");
        String ruleId = rs.getString("rule_id");
        String id = rs.getString("finding_id");
        boolean process = "PROCESS".equalsIgnoreCase(subjectType);
        String type = text(ruleId) ? ruleId : attribute(changes, "Finding type:", fallbackType(id));
        String semanticType = attribute(changes, "Finding type:", fallbackType(id));
        String severity = text(rs.getString("severity")) ? rs.getString("severity")
                : attribute(changes, "Severity:", "-");
        String confidence = formatConfidence(attribute(changes, "Confidence:", "-"));
        String intent = attribute(changes, "Malicious intent:", "UNKNOWN");
        String assessment = process ? "BEHAVIORAL_PATTERN" : assessment(type, rs.getString("trust_verdict"), intent);
        String subject = process ? processSubject(changes, rs.getString("subject_id"))
                : networkSubject(rs.getString("target_host"), rs.getObject("target_port", Integer.class));
        Instant lastSeen = instant(rs.getTimestamp("last_seen"));
        String status = rs.getString("status");
        String population = classify(status, lastSeen);
        return new Finding(id, rs.getString("agent_id"), display(rs.getString("display_name"), rs.getString("agent_id")),
                subject, subjectType, rs.getString("subject_id"), rs.getString("target_host"),
                rs.getObject("target_port", Integer.class), type, semanticType, severity, confidence, assessment,
                rs.getString("trust_verdict"), rs.getString("performance_verdict"),
                rs.getLong("occurrence_count"), status, population, instant(rs.getTimestamp("first_seen")),
                lastSeen, rs.getString("incident_id"), instant(rs.getTimestamp("observed_from")),
                instant(rs.getTimestamp("observed_to")), rs.getString("evidence_root"),
                parseNullable(rs.getString("rule_set")));
    }

    private String attribute(String raw, String prefix, String fallback) {
        if (!text(raw)) return fallback;
        try {
            JsonNode values = mapper.readTree(raw);
            if (!values.isArray()) return fallback;
            String wanted = prefix.toLowerCase(Locale.ROOT);
            for (JsonNode value : values) {
                String line = value.asText("");
                if (line.toLowerCase(Locale.ROOT).startsWith(wanted)) return line.substring(prefix.length()).trim();
            }
        } catch (Exception ignored) { }
        return fallback;
    }

    private static void equal(StringBuilder where, List<Object> args, String column, String value) {
        if (!text(value)) return;
        where.append(" AND upper(COALESCE(").append(column).append(",''))=upper(?)"); args.add(value.trim());
    }
    private static String orderBy(String sort, boolean ascending) {
        String column = switch (text(sort) ? sort.toLowerCase(Locale.ROOT) : "last_seen") {
            case "first_seen" -> "f.first_seen";
            case "occurrences", "count" -> "f.occurrence_count";
            case "agent" -> "COALESCE(NULLIF(a.display_name,''),f.agent_id)";
            case "target" -> "f.target_host";
            default -> "f.last_seen";
        };
        return column + (ascending ? " ASC" : " DESC") + ", f.finding_id" + (ascending ? " ASC" : " DESC");
    }
    public static void validateAge(Long older, Long newer) {
        if (older != null && newer != null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "olderThanSeconds and newerThanSeconds are mutually exclusive");
        Long value = older != null ? older : newer;
        if (value != null && (value <= 0 || value > MAX_AGE_SECONDS)) throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, "finding age must be between 1 and " + MAX_AGE_SECONDS + " seconds");
    }
    public static Duration parseAge(String raw) {
        String value = raw.trim().toLowerCase(Locale.ROOT);
        try {
            if (value.matches("[0-9]+[smhd]")) {
                long number = Long.parseLong(value.substring(0, value.length() - 1));
                return switch (value.charAt(value.length() - 1)) {
                    case 's' -> Duration.ofSeconds(number); case 'm' -> Duration.ofMinutes(number);
                    case 'h' -> Duration.ofHours(number); default -> Duration.ofDays(number);
                };
            }
            return Duration.parse(raw.toUpperCase(Locale.ROOT));
        } catch (RuntimeException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "invalid duration; use 30m, 24h, 7d or ISO-8601 PT24H");
        }
    }
    private static Target parseTarget(String raw) {
        int colon = raw.lastIndexOf(':');
        if (colon > 0 && colon < raw.length() - 1) {
            try {
                int port = Integer.parseInt(raw.substring(colon + 1));
                if (port >= 1 && port <= 65535) return new Target(raw.substring(0, colon), port);
            } catch (NumberFormatException ignored) { }
        }
        return new Target(raw, null);
    }
    private String processSubject(String changes, String subjectId) {
        String image = attribute(changes, "Process image:", "");
        if (text(image)) {
            String normalized = image.replace('\\', '/');
            int slash = normalized.lastIndexOf('/');
            String leaf = slash >= 0 ? normalized.substring(slash + 1) : normalized;
            if (text(leaf)) return leaf;
        }
        return text(subjectId) ? subjectId : "process";
    }
    private JsonNode parseNullable(String value) {
        if (!text(value)) return null;
        try { return mapper.readTree(value); }
        catch (Exception ignored) { return null; }
    }
    private static String networkSubject(String host, Integer port) { return !text(host) ? "-" : port == null ? host : host + ":" + port; }
    private static String fallbackType(String id) { if (!text(id)) return "-"; if (id.startsWith("FINDING-BEHAVIOR-")) return "BEHAVIOR"; if (id.startsWith("FINDING-TRANSFER-")) return "TRANSFER_BEHAVIOR"; return "CONNECTION_ASSURANCE"; }
    private static String assessment(String type, String trust, String intent) { if ("CONNECTION_ASSURANCE".equalsIgnoreCase(type)) return "PEER_" + upperOr(trust, "UNKNOWN"); return "INTENT_" + upperOr(intent, "UNKNOWN"); }
    private static String formatConfidence(String value) { if (!text(value) || "-".equals(value)) return "-"; try { return String.format(Locale.ROOT, "%.2f", Double.parseDouble(value)); } catch (NumberFormatException ignored) { return value; } }
    private static String upperOr(String value, String fallback) { return text(value) ? value.toUpperCase(Locale.ROOT) : fallback; }
    private static String display(String name, String id) { return text(name) ? name : id; }
    public String classify(String status, Instant lastSeen) {
        Instant now = clock.instant();
        if ("ACTIVE".equalsIgnoreCase(status)) return lastSeen != null && !lastSeen.isBefore(now.minus(currentActionableWindow))
                ? "CURRENT_ACTIONABLE" : "ACTIVE_HISTORICAL";
        if ("CANDIDATE".equalsIgnoreCase(status)) return lastSeen != null && !lastSeen.isBefore(now.minus(recentCandidateWindow))
                ? "RECENT_CANDIDATE" : "CANDIDATE_HISTORICAL";
        return "RETAINED_OTHER";
    }
    private static boolean text(String value) { return value != null && !value.isBlank(); }
    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }

    public record Filter(String agent, String trust, String performance, String population, String target,
                         String severity, String rule, String assessment, Long olderThanSeconds,
                         Long newerThanSeconds) {
        public static Filter defaults() { return new Filter(null, null, null, null, null, null, null, null, null, null); }
    }
    public record PageRequest(int limit, int offset, String sort, boolean ascending,
                              Instant cursorLastSeen, String cursorId) {}
    public record Page(List<Finding> items, long matched, boolean hasMore) {}
    public record Finding(String id, String agentId, String agentName, String subject, String subjectType,
                          String subjectId, String host, Integer port, String type, String semanticType, String severity,
                          String confidence, String assessment, String trust, String performance,
                          long count, String status, String population, Instant firstSeen, Instant lastSeen,
                          String incidentId, Instant observedFrom, Instant observedTo, String evidenceRoot,
                          JsonNode ruleSet) {}
    public record Summary(long retained, long currentActionable, long activeHistorical,
                          long recentCandidates, Instant oldestActive, long critical, long high,
                          long medium, long low) {}
    public record Selection(String where, List<Object> args) {}
    private record BuiltFilter(String where, List<Object> args) {}
    private record Target(String host, Integer port) {}
}
