package dev.neta.coordinator.upgrade;

import dev.neta.coordinator.release.GitHubAgentReleaseResolver;
import dev.neta.coordinator.release.ReleaseSourceType;
import dev.neta.coordinator.release.ResolvedAgentRelease;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AgentUpgradeRequestService {
    private final JdbcTemplate jdbc;
    private final GitHubAgentReleaseResolver releases;
    private final AgentUpgradeService upgrades;

    public AgentUpgradeRequestService(JdbcTemplate jdbc,
                                      GitHubAgentReleaseResolver releases,
                                      AgentUpgradeService upgrades) {
        this.jdbc = jdbc;
        this.releases = releases;
        this.upgrades = upgrades;
    }

    public AgentUpgrade request(String agentRef,
                                ReleaseSourceType sourceType,
                                String sourceRef,
                                boolean allowDevelopment) {
        if (agentRef == null || agentRef.isBlank()) throw new IllegalArgumentException("agent is required");
        if (sourceType == null) throw new IllegalArgumentException("source is required");
        if (sourceRef == null || sourceRef.isBlank()) throw new IllegalArgumentException("ref is required");
        if (sourceType == ReleaseSourceType.GIT_REF && !allowDevelopment) {
            throw new IllegalArgumentException("git-ref upgrades require allowDevelopment=true");
        }
        if (sourceType == ReleaseSourceType.RELEASE && allowDevelopment) {
            throw new IllegalArgumentException("allowDevelopment is only valid for git-ref upgrades");
        }

        List<TargetAgent> rows = jdbc.query("""
                SELECT agent_id, display_name, status, agent_os, agent_arch,
                       agent_version, agent_build_id, agent_git_commit, agent_artifact_sha256
                FROM agents
                WHERE agent_id=? OR display_name=?
                ORDER BY CASE WHEN agent_id=? THEN 0 ELSE 1 END
                LIMIT 1
                """, (rs, n) -> new TargetAgent(
                rs.getString("agent_id"),
                rs.getString("display_name"),
                rs.getString("status"),
                rs.getString("agent_os"),
                rs.getString("agent_arch"),
                rs.getString("agent_version"),
                rs.getString("agent_build_id"),
                rs.getString("agent_git_commit"),
                rs.getString("agent_artifact_sha256")),
                agentRef, agentRef, agentRef);
        if (rows.isEmpty()) throw new AgentUpgradeService.UpgradeRequestException("agent not found: " + agentRef);

        TargetAgent agent = rows.getFirst();
        if (!"ACTIVE".equals(agent.status())) {
            throw new AgentUpgradeService.UpgradeRequestException("agent is not ACTIVE");
        }
        if (agent.os() == null || agent.os().isBlank() || agent.arch() == null || agent.arch().isBlank()) {
            throw new AgentUpgradeService.UpgradeRequestException(
                    "agent has not reported a complete OS/architecture build identity");
        }

        ResolvedAgentRelease target = releases.resolve(sourceType, sourceRef, agent.os(), agent.arch());
        if (sameBuild(agent, target)) {
            throw new AgentUpgradeService.UpgradeRequestException(
                    "agent already runs requested build " + target.buildId() + " (" + target.gitCommit() + "); nothing to upgrade");
        }
        return upgrades.createRequest(agent.agentId(), target);
    }

    private static boolean sameBuild(TargetAgent agent, ResolvedAgentRelease target) {
        return equal(agent.version(), target.version())
                && equal(agent.buildId(), target.buildId())
                && equal(agent.gitCommit(), target.gitCommit());
    }

    private static boolean equal(String left, String right) {
        return left != null && right != null && left.trim().equalsIgnoreCase(right.trim());
    }

    private record TargetAgent(String agentId, String displayName, String status, String os, String arch,
                               String version, String buildId, String gitCommit, String artifactSha256) {}
}
