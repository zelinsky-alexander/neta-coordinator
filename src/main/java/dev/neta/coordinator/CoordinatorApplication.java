package dev.neta.coordinator;

import dev.neta.coordinator.cli.CoordinatorCliRunner;
import dev.neta.coordinator.config.AgentReleaseProperties;
import dev.neta.coordinator.config.CoordinatorProperties;
import dev.neta.coordinator.config.CoordinatorStorageProperties;
import java.util.Map;
import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties({CoordinatorProperties.class, CoordinatorStorageProperties.class, AgentReleaseProperties.class})
public class CoordinatorApplication {
    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(CoordinatorApplication.class);
        if (CoordinatorCliRunner.isCliInvocation(args)) {
            application.setWebApplicationType(WebApplicationType.NONE);
            application.setBannerMode(Banner.Mode.OFF);
            application.setDefaultProperties(Map.of(
                    "logging.level.root", "ERROR",
                    "spring.main.log-startup-info", "false"
            ));
            try (ConfigurableApplicationContext ignored = application.run(args)) {
                return;
            }
        }
        application.run(args);
    }
}
