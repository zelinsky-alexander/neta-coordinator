package dev.neta.coordinator.rules;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class RuleSetBootstrap implements ApplicationRunner {
    private static final String PERFORMANCE_RULE_ID = "NETA-PERF-001";
    private static final long TUNED_PERFORMANCE_REVISION = 2;
    private static final long TUNED_RETRANSMISSION_THRESHOLD = 5;

    private final RuleManagementService rules;

    public RuleSetBootstrap(RuleManagementService rules) {
        this.rules = rules;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            RuleManagementService.PublishedRuleSet active = rules.active();
            if (needsPerformanceTuning(active.bundle(), rules.currentRules())) {
                rules.publish("system:perf-false-positive-tuning");
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
        if (current == null || current.revision() < TUNED_PERFORMANCE_REVISION) return false;
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
}
