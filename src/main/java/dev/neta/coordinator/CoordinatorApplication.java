package dev.neta.coordinator;

import dev.neta.coordinator.config.CoordinatorProperties;
import dev.neta.coordinator.config.CoordinatorStorageProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties({CoordinatorProperties.class, CoordinatorStorageProperties.class})
public class CoordinatorApplication {
    public static void main(String[] args) {
        SpringApplication.run(CoordinatorApplication.class, args);
    }
}
