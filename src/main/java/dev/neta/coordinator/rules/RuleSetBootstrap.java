package dev.neta.coordinator.rules;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class RuleSetBootstrap implements ApplicationRunner {
    private static final String PERFORMANCE_RULE_ID = "PERF-001";
    private static final long TUNED_RETRANSMISSION_THRESHOLD = 5;

    private final RuleManagementService rules;

    public RuleSetBootstrap(RuleManagementService rules) {
        this.rules = rules;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            RuleManagementService.PublishedRuleSet active = rules.active();
            List<ManagedRule> currentRules = rules.currentRules();
            if (needsCatalogRefresh(active.bundle(), currentRules)) {
                rules.publish("system:rule-catalog-refresh");
            }
        } catch (IllegalStateException noPublishedRuleSet) {
            rules.publish("system-bootstrap");
        }
    }

    private static boolean needsPerformanceTuning(JsonNode activeBundle, List<ManagedRule> currentRules) {
        ManagedRule current = currentRules.stream()
                .filter(rule -> PERFORMANCE_RULE_ID.equals(rule.id()))
                .findFirst()
                .orElse(null);
        if (current == null) return false;
        if (current.parameters().path("retransmission_threshold").asLong(0) < TUNED_RETRANSMISSION_THRESHOLD) return false;

        JsonNode activeRules = activeBundle.path("rules");
        if (!activeRules.isArray()) return true;
        for (JsonNode rule : activeRules) {
            if (!PERFORMANCE_RULE_ID.equals(rule.path("id").asText())) continue;
            return rule.path("parameters").path("retransmission_threshold").asLong(0)
                    < TUNED_RETRANSMISSION_THRESHOLD;
        }
        return true;
    }

    private static boolean needsCatalogRefresh(JsonNode activeBundle, List<ManagedRule> currentRules) {
        if (needsPerformanceTuning(activeBundle, currentRules)) return true;
        JsonNode activeRules = activeBundle.path("rules");
        if (!activeRules.isArray()) return true;
        Set<String> publishedIds = new HashSet<>();
        activeRules.forEach(rule -> publishedIds.add(rule.path("id").asText()));
        return currentRules.stream().map(ManagedRule::id).anyMatch(id -> !publishedIds.contains(id));
    }
}
