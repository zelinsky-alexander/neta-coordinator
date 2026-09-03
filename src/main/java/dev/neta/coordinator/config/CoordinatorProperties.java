package dev.neta.coordinator.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("neta")
public record CoordinatorProperties(
        String fleetId,
        String bootstrapEnrollmentToken,
        Duration bootstrapTokenTtl,
        Enrollment enrollment,
        Security security,
        Liveness liveness) {

    public CoordinatorProperties {
        if (fleetId == null || fleetId.isBlank()) fleetId = "fleet-dev";
        if (bootstrapTokenTtl == null) bootstrapTokenTtl = Duration.ofHours(24);
        if (enrollment == null) enrollment = new Enrollment(null, null, "PKCS12", "neta-agent-issuer", null, Duration.ofDays(365));
        if (security == null) security = new Security(true, Duration.ofMinutes(2), Duration.ofMinutes(15));
        if (liveness == null) liveness = new Liveness(Duration.ofMinutes(7), Duration.ofMinutes(15));
    }

    public record Enrollment(
            String issuerKeyStore,
            String issuerKeyStorePassword,
            String issuerKeyStoreType,
            String issuerKeyAlias,
            String fleetCaFile,
            Duration certificateTtl) {
        public Enrollment {
            if (issuerKeyStoreType == null || issuerKeyStoreType.isBlank()) issuerKeyStoreType = "PKCS12";
            if (issuerKeyAlias == null || issuerKeyAlias.isBlank()) issuerKeyAlias = "neta-agent-issuer";
            if (certificateTtl == null) certificateTtl = Duration.ofDays(365);
        }
    }

    public record Security(boolean requireClientCertificate, Duration maxClockSkew, Duration maxMessageLifetime) {
        public Security {
            if (maxClockSkew == null) maxClockSkew = Duration.ofMinutes(2);
            if (maxMessageLifetime == null) maxMessageLifetime = Duration.ofMinutes(15);
        }
    }

    public record Liveness(Duration onlineThreshold, Duration offlineThreshold) {
        public Liveness {
            if (onlineThreshold == null) onlineThreshold = Duration.ofMinutes(7);
            if (offlineThreshold == null) offlineThreshold = Duration.ofMinutes(15);
            if (onlineThreshold.isNegative() || onlineThreshold.isZero())
                throw new IllegalArgumentException("liveness online threshold must be positive");
            if (offlineThreshold.compareTo(onlineThreshold) <= 0)
                throw new IllegalArgumentException("liveness offline threshold must be greater than online threshold");
        }
    }
}
