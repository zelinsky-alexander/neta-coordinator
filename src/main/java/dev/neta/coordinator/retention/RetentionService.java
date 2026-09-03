package dev.neta.coordinator.retention;

import dev.neta.coordinator.config.CoordinatorStorageProperties;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RetentionService {
    private final JdbcTemplate jdbc;
    private final CoordinatorStorageProperties properties;

    public RetentionService(JdbcTemplate jdbc, CoordinatorStorageProperties properties) {
        this.jdbc = jdbc;
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "${neta.storage.cleanup-interval:PT1H}")
    @Transactional
    public void cleanup() {
        Instant now = Instant.now();
        jdbc.update("DELETE FROM protocol_messages WHERE received_at < ?",
                Timestamp.from(now.minus(properties.protocolRetention())));
        jdbc.update("DELETE FROM endpoint_contact_history WHERE contact_at < ?",
                Timestamp.from(now.minus(properties.acceptedAuditRetention())));
        jdbc.update("DELETE FROM audit_events WHERE event_type='MESSAGE_ACCEPTED' AND created_at < ?",
                Timestamp.from(now.minus(properties.acceptedAuditRetention())));
        jdbc.update("DELETE FROM enrollment_tokens WHERE consumed_at IS NOT NULL AND consumed_at < ?",
                Timestamp.from(now.minus(properties.acceptedAuditRetention())));
        jdbc.update("DELETE FROM enrollment_tokens WHERE consumed_at IS NULL AND expires_at < ?",
                Timestamp.from(now.minus(properties.acceptedAuditRetention())));
    }
}
