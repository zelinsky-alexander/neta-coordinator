package dev.neta.coordinator.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("neta.storage")
public record CoordinatorStorageProperties(
        boolean retainHeartbeats,
        boolean auditHeartbeats,
        Duration protocolRetention,
        Duration acceptedAuditRetention,
        Duration cleanupInterval) {

    public CoordinatorStorageProperties {
        if (protocolRetention == null) protocolRetention = Duration.ofDays(7);
        if (acceptedAuditRetention == null) acceptedAuditRetention = Duration.ofDays(30);
        if (cleanupInterval == null) cleanupInterval = Duration.ofHours(1);
    }
}
