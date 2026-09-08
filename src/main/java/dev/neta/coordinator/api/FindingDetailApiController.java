package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/findings")
public class FindingDetailApiController {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public FindingDetailApiController(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @GetMapping("/{findingId}/detail")
    public FindingDetail detail(@PathVariable String findingId) {
        List<FindingDetail> rows = jdbc.query("""
                SELECT f.finding_id,f.finding_key,f.message_id,f.agent_id,a.display_name,
                       f.target_host,f.target_port,f.subject_type,f.subject_id,f.severity,f.rule_id,
                       f.observed_from,f.observed_to,f.changes::text AS changes,
                       f.performance_verdict,f.trust_verdict,f.rule_set::text AS rule_set,
                       f.evidence_root,f.payload::text AS finding_payload,f.received_at,
                       f.first_seen,f.last_seen,f.occurrence_count,f.status,m.incident_id,
                       pm.protocol,pm.schema_version,pm.message_type,pm.created_at AS message_created_at,
                       pm.expires_at AS message_expires_at,pm.sequence,pm.correlation_id,pm.payload_hash,
                       pm.signature::text AS message_signature,pm.received_at AS message_received_at
                FROM findings f
                JOIN agents a ON a.agent_id=f.agent_id
                LEFT JOIN incident_findings m ON m.finding_id=f.finding_id
                LEFT JOIN protocol_messages pm ON pm.agent_id=f.agent_id AND pm.message_id=f.message_id
                WHERE f.finding_id=?
                """, (rs, n) -> {
                    String subjectType = rs.getString("subject_type");
                    String subjectId = rs.getString("subject_id");
                    String changesText = rs.getString("changes");
                    String ruleId = rs.getString("rule_id");
                    String storedSeverity = rs.getString("severity");
                    String host = rs.getString("target_host");
                    Integer port = rs.getObject("target_port", Integer.class);
                    boolean process = "PROCESS".equalsIgnoreCase(subjectType);
                    String type = process && text(ruleId)
                            ? ruleId
                            : findingAttribute(changesText, "Finding type:", fallbackFindingType(rs.getString("finding_id")));
                    String severity = text(storedSeverity)
                            ? storedSeverity
                            : findingAttribute(changesText, "Severity:", "-");
                    String confidence = formatConfidence(findingAttribute(changesText, "Confidence:", "-"));
                    String intent = findingAttribute(changesText, "Malicious intent:", "UNKNOWN");
                    String subject = process ? processSubjectDisplay(changesText, subjectId) : networkSubject(host, port);
                    String assessment = process ? "BEHAVIORAL_PATTERN" : assessment(type, rs.getString("trust_verdict"), intent);

                    ProtocolContext protocol = rs.getString("protocol") == null ? null : new ProtocolContext(
                            rs.getString("protocol"), rs.getObject("schema_version", Integer.class),
                            rs.getString("message_type"), instant(rs.getTimestamp("message_created_at")),
                            instant(rs.getTimestamp("message_expires_at")), rs.getObject("sequence", Long.class),
                            rs.getString("correlation_id"), rs.getString("payload_hash"),
                            json(rs.getString("message_signature")), instant(rs.getTimestamp("message_received_at")));

                    return new FindingDetail(
                            rs.getString("finding_id"), rs.getString("finding_key"), rs.getString("message_id"),
                            rs.getString("agent_id"), display(rs.getString("display_name"), rs.getString("agent_id")),
                            subject, subjectType, subjectId, host, port, type, ruleId, severity, confidence, assessment,
                            rs.getString("trust_verdict"), rs.getString("performance_verdict"),
                            rs.getString("status"), rs.getLong("occurrence_count"),
                            instant(rs.getTimestamp("first_seen")), instant(rs.getTimestamp("last_seen")),
                            instant(rs.getTimestamp("received_at")), instant(rs.getTimestamp("observed_from")),
                            instant(rs.getTimestamp("observed_to")), rs.getString("incident_id"),
                            rs.getString("evidence_root"), json(changesText), json(rs.getString("rule_set")),
                            json(rs.getString("finding_payload")), protocol);
                }, findingId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "finding not found");
        return rows.getFirst();
    }

    private JsonNode json(String value) {
        if (!text(value)) return mapper.nullNode();
        try { return mapper.readTree(value); }
        catch (Exception e) { return mapper.getNodeFactory().textNode(value); }
    }

    private String findingAttribute(String changes, String prefix, String fallback) {
        if (!text(changes)) return fallback;
        try {
            JsonNode node = mapper.readTree(changes);
            if (node != null && node.isArray()) {
                for (JsonNode item : node) {
                    if (!item.isTextual()) continue;
                    String value = item.asText();
                    if (value.regionMatches(true, 0, prefix, 0, prefix.length())) {
                        String extracted = value.substring(prefix.length()).trim();
                        if (!extracted.isEmpty()) return extracted;
                    }
                }
            }
        } catch (Exception ignored) { }
        return fallback;
    }

    private String processSubjectDisplay(String changes, String subjectId) {
        String image = findingAttribute(changes, "Process image:", "");
        if (text(image)) {
            String normalized = image.replace('\\', '/');
            int slash = normalized.lastIndexOf('/');
            String leaf = slash >= 0 ? normalized.substring(slash + 1) : normalized;
            if (text(leaf)) return leaf;
        }
        return text(subjectId) ? subjectId : "process";
    }

    private static String networkSubject(String host, Integer port) {
        if (!text(host)) return "-";
        return port == null ? host : host + ":" + port;
    }

    private static String fallbackFindingType(String id) {
        if (!text(id)) return "-";
        if (id.startsWith("FINDING-BEHAVIOR-")) return "BEHAVIOR";
        if (id.startsWith("FINDING-TRANSFER-")) return "TRANSFER_BEHAVIOR";
        return "CONNECTION_ASSURANCE";
    }

    private static String formatConfidence(String confidence) {
        if (!text(confidence) || "-".equals(confidence)) return "-";
        try { return String.format(Locale.ROOT, "%.2f", Double.parseDouble(confidence)); }
        catch (NumberFormatException ignored) { return confidence; }
    }

    private static String assessment(String findingType, String trust, String maliciousIntent) {
        String type = upper(findingType);
        if ("CONNECTION_ASSURANCE".equals(type)) {
            String peer = upper(trust);
            return "-".equals(peer) ? "PEER_UNKNOWN" : "PEER_" + peer;
        }
        String intent = upper(maliciousIntent);
        return "INTENT_" + ("-".equals(intent) ? "UNKNOWN" : intent);
    }

    private static String upper(String value) { return text(value) ? value.toUpperCase(Locale.ROOT) : "-"; }
    private static boolean text(String value) { return value != null && !value.isBlank(); }
    private static String display(String name, String id) { return text(name) ? name : id; }
    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }

    public record ProtocolContext(String protocol, Integer schemaVersion, String messageType,
                                  Instant createdAt, Instant expiresAt, Long sequence,
                                  String correlationId, String payloadHash,
                                  JsonNode signature, Instant receivedAt) {}

    public record FindingDetail(String id, String findingKey, String messageId,
                                String agentId, String agentName,
                                String subject, String subjectType, String subjectId,
                                String host, Integer port, String type, String ruleId,
                                String severity, String confidence, String assessment,
                                String trust, String performance, String status, long count,
                                Instant firstSeen, Instant lastSeen, Instant receivedAt,
                                Instant observedFrom, Instant observedTo, String incidentId,
                                String evidenceRoot, JsonNode changes, JsonNode ruleSet,
                                JsonNode payload, ProtocolContext protocol) {}
}
