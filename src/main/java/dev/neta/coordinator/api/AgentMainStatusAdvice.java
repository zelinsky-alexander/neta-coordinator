package dev.neta.coordinator.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.neta.coordinator.config.AgentReleaseProperties;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

@ControllerAdvice
public class AgentMainStatusAdvice implements ResponseBodyAdvice<Object> {
    private static final Duration CACHE_TTL = Duration.ofSeconds(60);
    private static final String COMMIT_PATTERN = "[0-9a-f]{40}";

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final AgentReleaseProperties releases;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    private volatile String cachedMainCommit;
    private volatile Instant cachedAt = Instant.EPOCH;

    public AgentMainStatusAdvice(JdbcTemplate jdbc, ObjectMapper mapper, AgentReleaseProperties releases) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.releases = releases;
    }

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request, ServerHttpResponse response) {
        if (body == null) return null;
        String path = request.getURI().getPath();
        String mainCommit = latestMainCommit();

        if ("/api/v1/operator/endpoints".equals(path) && body instanceof String text) {
            return decorateEndpointTable(text, mainCommit);
        }
        if (("/api/v1/operator/endpoint".equals(path) || path.startsWith("/api/v1/operator/endpoints/")) && body instanceof String text) {
            return decorateEndpointDetail(text, mainCommit);
        }
        if ("/api/v1/agents".equals(path) || path.startsWith("/api/v1/agents/")) {
            return decorateAgentJson(body, mainCommit);
        }
        return body;
    }

    private Object decorateAgentJson(Object body, String mainCommit) {
        JsonNode root = mapper.valueToTree(body);
        if (root instanceof ObjectNode object) {
            JsonNode items = object.get("items");
            if (items != null && items.isArray()) {
                for (JsonNode item : items) if (item instanceof ObjectNode agent) decorateAgentNode(agent, mainCommit);
            } else if (object.has("gitCommit")) {
                decorateAgentNode(object, mainCommit);
            }
        }
        return root;
    }

    private void decorateAgentNode(ObjectNode agent, String mainCommit) {
        String commit = text(agent.get("gitCommit"));
        String status = status(commit, mainCommit);
        agent.put("mainStatus", status);
        if (mainCommit != null) agent.put("mainCommit", mainCommit);
        JsonNode buildNode = agent.get("build");
        if (buildNode != null && buildNode.isTextual() && !buildNode.asText().isBlank()) {
            String build = buildNode.asText();
            if (!build.contains("[LATEST]") && !build.contains("[NOT_LATEST]") && !build.contains("[UNKNOWN]")) {
                agent.put("build", build + " [" + status + "]");
            }
        }
    }

    private String decorateEndpointDetail(String text, String mainCommit) {
        String commit = null;
        for (String line : text.split("\\R")) {
            if (line.startsWith("Git commit:")) {
                commit = line.substring("Git commit:".length()).trim();
                break;
            }
        }
        String marker = String.format("%-20s %s%n", "Main status:", status(commit, mainCommit));
        String main = mainCommit == null ? "" : String.format("%-20s %s%n", "Main commit:", mainCommit);
        int heartbeat = text.indexOf("\nHeartbeat:");
        if (heartbeat >= 0) return text.substring(0, heartbeat) + "\n" + marker + main + text.substring(heartbeat);
        return text + (text.endsWith("\n") ? "" : "\n") + marker + main;
    }

    private String decorateEndpointTable(String text, String mainCommit) {
        Map<String, String> commits = new HashMap<>();
        jdbc.query("SELECT agent_id,display_name,agent_git_commit FROM agents", rs -> {
            String id = rs.getString("agent_id");
            String name = rs.getString("display_name");
            String commit = rs.getString("agent_git_commit");
            if (id != null) commits.put(id, commit);
            if (name != null && !name.isBlank()) commits.put(name, commit);
        });

        List<String> lines = text.lines().toList();
        if (lines.isEmpty()) return text;
        StringBuilder out = new StringBuilder();
        out.append(lines.getFirst()).append("  MAIN\n");
        if (lines.size() > 1) out.append(lines.get(1)).append("------------\n");
        for (int i = 2; i < lines.size(); ++i) {
            String line = lines.get(i);
            String name = line.stripLeading().split("\\s+", 2)[0];
            out.append(line).append("  ").append(status(commits.get(name), mainCommit)).append('\n');
        }
        return out.toString();
    }

    private String latestMainCommit() {
        Instant now = Instant.now();
        String current = cachedMainCommit;
        if (current != null && Duration.between(cachedAt, now).compareTo(CACHE_TTL) < 0) return current;
        synchronized (this) {
            current = cachedMainCommit;
            if (current != null && Duration.between(cachedAt, now).compareTo(CACHE_TTL) < 0) return current;
            try {
                String owner = segment(releases.owner());
                String repo = segment(releases.repository());
                String base = releases.apiBase().replaceAll("/+$", "");
                URI uri = URI.create(base + "/repos/" + owner + "/" + repo + "/commits/main");
                HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofSeconds(5))
                        .header("Accept", "application/vnd.github+json")
                        .header("User-Agent", "neta-coordinator")
                        .GET();
                if (!releases.githubToken().isBlank() && "api.github.com".equalsIgnoreCase(uri.getHost())) {
                    builder.header("Authorization", "Bearer " + releases.githubToken());
                    builder.header("X-GitHub-Api-Version", "2022-11-28");
                }
                HttpResponse<String> result = http.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (result.statusCode() >= 200 && result.statusCode() < 300) {
                    String sha = mapper.readTree(result.body()).path("sha").asText("").trim().toLowerCase(Locale.ROOT);
                    if (sha.matches(COMMIT_PATTERN)) {
                        cachedMainCommit = sha;
                        cachedAt = now;
                        return sha;
                    }
                }
            } catch (IOException ignored) {
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException ignored) {
            }
            cachedAt = now;
            return cachedMainCommit;
        }
    }

    private static String status(String agentCommit, String mainCommit) {
        if (agentCommit == null || !agentCommit.trim().toLowerCase(Locale.ROOT).matches(COMMIT_PATTERN) || mainCommit == null) return "UNKNOWN";
        return agentCommit.trim().equalsIgnoreCase(mainCommit) ? "LATEST" : "NOT_LATEST";
    }

    private static String text(JsonNode node) {
        return node != null && node.isTextual() ? node.asText() : null;
    }

    private static String segment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
