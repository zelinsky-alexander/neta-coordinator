package dev.neta.coordinator.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.neta.coordinator.security.PeerCertificateService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** RM4.1 bounded mTLS ingestion of normalized endpoint artifact evidence snapshots. */
@RestController
@RequestMapping("/api/v1/agent/artifacts")
public class ArtifactEvidenceIngestController {
    private static final int MAX_ITEMS = 64;
    private static final int MAX_MATCHES_PER_ITEM = 256;
    private static final int MAX_SERIALIZED_BYTES = 1024 * 1024;
    private static final Pattern SHA256 = Pattern.compile("^(?:sha256:)?[0-9a-fA-F]{64}$");

    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    private final PeerCertificateService certificates;

    public ArtifactEvidenceIngestController(JdbcTemplate jdbc,
                                            ObjectMapper json,
                                            PeerCertificateService certificates) {
        this.jdbc = jdbc;
        this.json = json;
        this.certificates = certificates;
    }

    @PostMapping("/evidence")
    public ArtifactEvidenceAck ingest(HttpServletRequest servletRequest,
                                      @RequestBody JsonNode request) {
        String agentId = authenticatedAgent(servletRequest);
        ObjectNode bounded = validateAndNormalize(request);
        String serialized = write(bounded);
        if (serialized.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_SERIALIZED_BYTES)
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                    "artifact evidence summary exceeds 1 MiB");

        String messageId = "rm4-artifact-" + UUID.randomUUID();
        String evidenceRoot = text(bounded, "evidence_root");
        jdbc.update("""
                INSERT INTO evidence_summaries(agent_id,message_id,correlation_id,evidence_root,summary)
                VALUES (?,?,NULL,?,CAST(? AS jsonb))
                """, agentId, messageId, evidenceRoot, serialized);

        return new ArtifactEvidenceAck(true, agentId, messageId,
                bounded.withArray("artifact_evidence").size());
    }

    private ObjectNode validateAndNormalize(JsonNode request) {
        if (request == null || !request.isObject())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "JSON object body is required");
        JsonNode rawItems = request.get("artifact_evidence");
        if (rawItems == null || !rawItems.isArray())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "artifact_evidence array is required");
        if (rawItems.size() > MAX_ITEMS)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "artifact_evidence accepts at most " + MAX_ITEMS + " items per request");

        ObjectNode normalized = json.createObjectNode();
        if (request.hasNonNull("evidence_root")) normalized.put("evidence_root", request.get("evidence_root").asText());
        ArrayNode items = normalized.putArray("artifact_evidence");
        for (JsonNode item : rawItems) items.add(validateItem(item));
        return normalized;
    }

    private ObjectNode validateItem(JsonNode item) {
        if (item == null || !item.isObject())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "artifact evidence item must be an object");
        String sha = requiredText(item, "artifact_sha256");
        if (!SHA256.matcher(sha).matches())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "artifact_sha256 must be a SHA-256 value");
        if (sha.regionMatches(true, 0, "sha256:", 0, 7)) sha = sha.substring(7);
        sha = sha.toLowerCase(java.util.Locale.ROOT);
        String provider = requiredText(item, "provider_name");
        if (provider.length() > 128)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "provider_name is too long");

        JsonNode matches = item.get("matches");
        if (matches != null && !matches.isArray())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "matches must be an array");
        if (matches != null && matches.size() > MAX_MATCHES_PER_ITEM)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "matches accepts at most " + MAX_MATCHES_PER_ITEM + " entries per artifact");

        ObjectNode out = json.createObjectNode();
        out.put("artifact_sha256", sha);
        copyText(item, out, "artifact_path", 4096);
        copyUnsignedLong(item, out, "artifact_size");
        out.put("provider_name", provider);
        copyText(item, out, "provider_version", 256);
        copyText(item, out, "ruleset_id", 256);
        copyHash(item, out, "ruleset_sha256");
        copyText(item, out, "scan_state", 64);
        copyText(item, out, "detail", 4096);
        copyText(item, out, "observed_at", 128);
        copyUnsignedLong(item, out, "observation_count");
        out.set("matches", matches == null ? json.createArrayNode() : matches.deepCopy());
        return out;
    }

    private String authenticatedAgent(HttpServletRequest request) {
        String fingerprint = certificates.sha256Fingerprint(request)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                        "agent mTLS certificate is required"));
        List<String> agents = jdbc.query(
                "SELECT agent_id FROM agents WHERE certificate_sha256=? AND status='ACTIVE' LIMIT 2",
                (rs, n) -> rs.getString(1), fingerprint);
        if (agents.size() != 1)
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "agent certificate is not bound to one active endpoint");
        return agents.getFirst();
    }

    private static String requiredText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " is required");
        return value.asText().trim();
    }

    private static void copyText(JsonNode from, ObjectNode to, String field, int maxLength) {
        JsonNode value = from.get(field);
        if (value == null || value.isNull()) return;
        if (!value.isTextual())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " must be a string");
        String text = value.asText();
        if (text.length() > maxLength)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " is too long");
        to.put(field, text);
    }

    private static void copyHash(JsonNode from, ObjectNode to, String field) {
        JsonNode value = from.get(field);
        if (value == null || value.isNull() || value.asText().isBlank()) return;
        if (!value.isTextual() || !SHA256.matcher(value.asText()).matches())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " must be a SHA-256 value");
        String text = value.asText();
        if (text.regionMatches(true, 0, "sha256:", 0, 7)) text = text.substring(7);
        to.put(field, text.toLowerCase(java.util.Locale.ROOT));
    }

    private static void copyUnsignedLong(JsonNode from, ObjectNode to, String field) {
        JsonNode value = from.get(field);
        if (value == null || value.isNull()) return;
        if (!value.canConvertToLong() || value.asLong() < 0)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " must be a non-negative integer");
        to.put(field, value.asLong());
    }

    private String write(JsonNode value) {
        try { return json.writeValueAsString(value); }
        catch (JsonProcessingException e) { throw new IllegalStateException("cannot serialize artifact evidence summary", e); }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() && !value.asText().isBlank() ? value.asText() : null;
    }

    public record ArtifactEvidenceAck(boolean accepted, String agentId, String messageId, int itemCount) {}
}
