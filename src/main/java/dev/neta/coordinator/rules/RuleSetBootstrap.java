package dev.neta.coordinator.rules;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class RuleSetBootstrap implements ApplicationRunner {
    private final RuleManagementService rules;

    public RuleSetBootstrap(RuleManagementService rules) {
        this.rules = rules;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            rules.active();
        } catch (IllegalStateException noPublishedRuleSet) {
            rules.publish("system-bootstrap");
        }
    }
}
