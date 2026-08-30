package dev.neta.coordinator.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("neta")
public record CoordinatorProperties(
        String fleetId,
        String bootstrapEnrollmentToken,
        Duration bootstrapTokenTtl,
        Security security) {

    public CoordinatorProperties {
        if (fleetId == null || fleetId.isBlank()) fleetId = "fleet-dev";
        if (bootstrapTokenTtl == null) bootstrapTokenTtl = Duration.ofHours(24);
        if (security == null) security = new Security(true, Duration.ofMinutes(2), Duration.ofMinutes(15));
    }

    public record Security(boolean requireClientCertificate, Duration maxClockSkew, Duration maxMessageLifetime) {
        public Security {
            if (maxClockSkew == null) maxClockSkew = Duration.ofMinutes(2);
            if (maxMessageLifetime == null) maxMessageLifetime = Duration.ofMinutes(15);
        }
    }
}
