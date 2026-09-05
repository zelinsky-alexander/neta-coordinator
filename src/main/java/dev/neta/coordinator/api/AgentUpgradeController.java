package dev.neta.coordinator.api;

import dev.neta.coordinator.upgrade.AgentUpgrade;
import dev.neta.coordinator.upgrade.AgentUpgradeService;
import dev.neta.coordinator.upgrade.AgentUpgradeService.UpgradeRequestException;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/operator")
public class AgentUpgradeController {
    private final AgentUpgradeService upgrades;

    public AgentUpgradeController(AgentUpgradeService upgrades) {
        this.upgrades = upgrades;
    }

    @GetMapping(value = "/upgrades", produces = MediaType.TEXT_PLAIN_VALUE)
    public String upgrades(@RequestParam(required = false) String agent,
                           @RequestParam(defaultValue = "20") int limit) {
        List<AgentUpgrade> rows = upgrades.recent(agent, limit);
        StringBuilder out = new StringBuilder();
        out.append(String.format("%-12s %-22s %-14s %-14s %-12s %-18s %-9s %s%n",
                "UPGRADE", "AGENT", "FROM", "TARGET", "STATUS", "PLATFORM", "SOURCE", "REQUESTED"));
        out.append("------------------------------------------------------------------------------------------------------------------------\n");
        for (AgentUpgrade row : rows) {
            out.append(String.format("%-12s %-22s %-14s %-14s %-12s %-18s %-9s %s%n",
                    shortId(row.upgradeId()), trim(row.agentId(), 22), trim(build(row.fromVersion(), row.fromBuildId()), 14),
                    trim(build(row.targetVersion(), row.targetBuildId()), 14), row.status(),
                    trim(row.targetOs() + "/" + row.targetArch(), 18),
                    row.sourceType().name().toLowerCase().replace('_', '-'), row.requestedAt()));
        }
        if (rows.isEmpty()) out.append("(no upgrade requests)\n");
        return out.toString();
    }

    @GetMapping(value = "/upgrade", produces = MediaType.TEXT_PLAIN_VALUE)
    public String upgrade(@RequestParam("id") String id) {
        try {
            return detail(upgrades.get(UUID.fromString(id)));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid upgrade id", e);
        } catch (UpgradeRequestException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e);
        }
    }

    private static String detail(AgentUpgrade row) {
        StringBuilder out = new StringBuilder();
        line(out, "Upgrade ID", row.upgradeId().toString());
        line(out, "Agent ID", row.agentId());
        line(out, "Status", row.status().name());
        line(out, "From version", value(row.fromVersion()));
        line(out, "From build", value(row.fromBuildId()));
        line(out, "From commit", value(row.fromGitCommit()));
        line(out, "From artifact SHA", value(row.fromArtifactSha256()));
        line(out, "Source type", row.sourceType().name());
        line(out, "Source ref", row.sourceRef());
        line(out, "Source commit", row.sourceCommit());
        line(out, "Target version", row.targetVersion());
        line(out, "Target build", row.targetBuildId());
        line(out, "Target commit", row.targetGitCommit());
        line(out, "Platform", row.targetOs() + "/" + row.targetArch());
        line(out, "Artifact", row.artifactName());
        line(out, "Artifact URL", row.artifactUrl());
        line(out, "Artifact SHA-256", row.artifactSha256());
        line(out, "Requested", instant(row.requestedAt()));
        line(out, "Delivered", instant(row.deliveredAt()));
        line(out, "Download started", instant(row.downloadStartedAt()));
        line(out, "Install started", instant(row.installStartedAt()));
        line(out, "Local healthy", instant(row.localHealthyAt()));
        line(out, "Confirmed", instant(row.confirmedAt()));
        line(out, "Failed", instant(row.failedAt()));
        line(out, "Rolled back", instant(row.rolledBackAt()));
        line(out, "Failure code", value(row.failureCode()));
        line(out, "Failure message", value(row.failureMessage()));
        return out.toString();
    }

    private static String build(String version, String build) {
        if (version == null || version.isBlank()) return "-";
        return build == null || build.isBlank() ? version : version + "/" + build;
    }

    private static String instant(java.time.Instant value) { return value == null ? "-" : value.toString(); }
    private static String value(String value) { return value == null || value.isBlank() ? "-" : value; }
    private static String shortId(UUID id) { return id == null ? "-" : id.toString().substring(0, 8); }
    private static String trim(String value, int width) {
        if (value == null || value.isBlank()) return "-";
        return value.length() <= width ? value : value.substring(0, width - 1) + "…";
    }
    private static void line(StringBuilder out, String label, String value) {
        out.append(String.format("%-21s %s%n", label + ":", value(value)));
    }
}
