package dev.neta.coordinator.api;

import dev.neta.coordinator.release.GitHubAgentReleaseResolver;
import dev.neta.coordinator.release.GitHubAgentReleaseResolver.ResolutionException;
import dev.neta.coordinator.release.ReleaseSourceType;
import dev.neta.coordinator.release.ResolvedAgentRelease;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/operator")
public class AgentReleaseController {
    private final GitHubAgentReleaseResolver resolver;

    public AgentReleaseController(GitHubAgentReleaseResolver resolver) {
        this.resolver = resolver;
    }

    @GetMapping(value = "/release-resolve", produces = MediaType.TEXT_PLAIN_VALUE)
    public String resolve(@RequestParam(defaultValue = "release") String source,
                          @RequestParam("ref") String ref,
                          @RequestParam("os") String os,
                          @RequestParam("arch") String arch) {
        try {
            ResolvedAgentRelease release = resolver.resolve(ReleaseSourceType.parse(source), ref, os, arch);
            return detail(release);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        } catch (ResolutionException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, e.getMessage(), e);
        }
    }

    @GetMapping(value = "/releases", produces = MediaType.TEXT_PLAIN_VALUE)
    public String releases(@RequestParam(defaultValue = "20") int limit) {
        List<ResolvedAgentRelease> rows = resolver.recent(limit);
        StringBuilder out = new StringBuilder();
        out.append(String.format("%-9s %-24s %-12s %-16s %-18s %-12s %s%n",
                "SOURCE", "REF", "VERSION", "BUILD", "PLATFORM", "COMMIT", "ARTIFACT"));
        out.append("------------------------------------------------------------------------------------------------------------------------\n");
        for (ResolvedAgentRelease row : rows) {
            out.append(String.format("%-9s %-24s %-12s %-16s %-18s %-12s %s%n",
                    row.sourceType() == ReleaseSourceType.RELEASE ? "release" : "git-ref",
                    trim(row.sourceRef(), 24), trim(row.version(), 12), trim(row.buildId(), 16),
                    trim(row.os() + "/" + row.arch(), 18), shortCommit(row.sourceCommit()), row.artifactName()));
        }
        if (rows.isEmpty()) out.append("(no resolved releases)\n");
        return out.toString();
    }

    private static String detail(ResolvedAgentRelease row) {
        StringBuilder out = new StringBuilder();
        line(out, "Source", row.sourceType() == ReleaseSourceType.RELEASE ? "release" : "git-ref");
        line(out, "Requested ref", row.sourceRef());
        line(out, "Resolved commit", row.sourceCommit());
        line(out, "Version", row.version());
        line(out, "Build ID", row.buildId());
        line(out, "Manifest commit", row.gitCommit());
        line(out, "Platform", row.os() + "/" + row.arch());
        line(out, "Artifact", row.artifactName());
        line(out, "Artifact URL", row.artifactUrl());
        line(out, "Artifact SHA-256", row.artifactSha256());
        line(out, "Published", row.publishedAt() == null ? "-" : row.publishedAt().toString());
        return out.toString();
    }

    private static void line(StringBuilder out, String label, String value) {
        out.append(String.format("%-18s %s%n", label + ":", value == null || value.isBlank() ? "-" : value));
    }

    private static String trim(String value, int width) {
        if (value == null || value.isBlank()) return "-";
        return value.length() <= width ? value : value.substring(0, width - 1) + "…";
    }

    private static String shortCommit(String value) {
        return value == null || value.length() < 12 ? value : value.substring(0, 12);
    }
}
