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
                SELECT agent_id, display_name, status, agent_os, agent_arch
                FROM agents
                WHERE agent_id=? OR display_name=?
                ORDER BY CASE WHEN agent_id=? THEN 0 ELSE 1 END
                LIMIT 1
                """, (rs, n) -> new TargetAgent(
                rs.getString("agent_id"),
                rs.getString("display_name"),
                rs.getString("status"),
                rs.getString("agent_os"),
                rs.getString("agent_arch")),
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
        return upgrades.createRequest(agent.agentId(), target);
    }

    private record TargetAgent(String agentId, String displayName, String status, String os, String arch) {}
}
