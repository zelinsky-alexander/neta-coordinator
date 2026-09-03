package dev.neta.coordinator.api;

import dev.neta.coordinator.config.CoordinatorStorageProperties;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/operator")
public class StorageOperatorController {
    private final JdbcTemplate jdbc;
    private final CoordinatorStorageProperties storage;

    public StorageOperatorController(JdbcTemplate jdbc, CoordinatorStorageProperties storage) {
        this.jdbc = jdbc;
        this.storage = storage;
    }

    @GetMapping(value = "/storage", produces = MediaType.TEXT_PLAIN_VALUE)
    public String storage() {
        Instant now = Instant.now();
        Long dbBytes = jdbc.queryForObject("SELECT pg_database_size(current_database())", Long.class);

        List<TableStat> tables = List.of(
                table("agents", "last_seen_at"),
                table("findings", "last_seen"),
                table("incidents", "last_seen"),
                table("incident_findings", null),
                table("endpoint_contact_history", "received_at"),
                table("protocol_messages", "received_at"),
                table("audit_events", "created_at"),
                table("evidence_summaries", "received_at"),
                table("corroboration_requests", "created_at"),
                table("corroboration_responses", "received_at"),
                table("enrollment_tokens", "created_at"));

        StringBuilder out = new StringBuilder();
        out.append("NETA Coordinator Storage\n");
        out.append("=================================\n");
        line(out, "Database size", humanBytes(dbBytes == null ? 0L : dbBytes));
        line(out, "Heartbeat payloads", storage.retainHeartbeats() ? "RETAINED" : "CURRENT ONLY");
        line(out, "Heartbeat audit", storage.auditHeartbeats() ? "ENABLED" : "DISABLED");
        line(out, "Protocol retention", storage.protocolRetention().toString());
        line(out, "Audit/contact retention", storage.acceptedAuditRetention().toString());
        line(out, "Cleanup interval", storage.cleanupInterval().toString());

        out.append("\nTable usage\n");
        out.append("---------------------------------\n");
        out.append(String.format("%-28s %10s %12s %12s %12s%n", "TABLE", "ROWS", "SIZE", "OLDEST", "NEWEST"));
        for (TableStat stat : tables) {
            out.append(String.format("%-28s %10d %12s %12s %12s%n",
                    stat.name(), stat.rows(), humanBytes(stat.bytes()),
                    relativeAge(stat.oldest(), now), relativeAge(stat.newest(), now)));
        }

        out.append("\nRetention windows\n");
        out.append("---------------------------------\n");
        retentionLine(out, "protocol_messages", storage.protocolRetention(), oldest("protocol_messages", "received_at"), now);
        retentionLine(out, "audit_events MESSAGE_ACCEPTED", storage.acceptedAuditRetention(),
                oldestWhere("audit_events", "created_at", "event_type='MESSAGE_ACCEPTED'"), now);
        retentionLine(out, "endpoint_contact_history", storage.acceptedAuditRetention(), oldest("endpoint_contact_history", "received_at"), now);
        retentionLine(out, "consumed enrollment tokens", storage.acceptedAuditRetention(),
                oldestWhere("enrollment_tokens", "consumed_at", "consumed_at IS NOT NULL"), now);

        return out.toString();
    }

    private TableStat table(String table, String timeColumn) {
        long rows = count(table);
        long bytes = relationBytes(table);
        Instant oldest = timeColumn == null ? null : oldest(table, timeColumn);
        Instant newest = timeColumn == null ? null : newest(table, timeColumn);
        return new TableStat(table, rows, bytes, oldest, newest);
    }

    private long count(String table) {
        Long value = jdbc.queryForObject("SELECT count(*) FROM " + table, Long.class);
        return value == null ? 0L : value;
    }

    private long relationBytes(String table) {
        Long value = jdbc.queryForObject("SELECT pg_total_relation_size('" + table + "'::regclass)", Long.class);
        return value == null ? 0L : value;
    }

    private Instant oldest(String table, String column) {
        return aggregateInstant("SELECT min(" + column + ") FROM " + table);
    }

    private Instant newest(String table, String column) {
        return aggregateInstant("SELECT max(" + column + ") FROM " + table);
    }

    private Instant oldestWhere(String table, String column, String predicate) {
        return aggregateInstant("SELECT min(" + column + ") FROM " + table + " WHERE " + predicate);
    }

    private Instant aggregateInstant(String sql) {
        Timestamp ts = jdbc.queryForObject(sql, Timestamp.class);
        return ts == null ? null : ts.toInstant();
    }

    private static void retentionLine(StringBuilder out, String name, Duration configured, Instant oldest, Instant now) {
        String observed = oldest == null ? "empty" : relativeAge(oldest, now) + " old";
        out.append(String.format("%-30s configured=%-8s oldest=%s%n", name, configured, observed));
    }

    private static void line(StringBuilder out, String label, String value) {
        out.append(String.format("%-24s %s%n", label + ":", value));
    }

    private static String relativeAge(Instant then, Instant now) {
        if (then == null) return "-";
        long seconds = Math.max(0, Duration.between(then, now).getSeconds());
        if (seconds < 60) return seconds + " sec";
        long minutes = seconds / 60;
        if (minutes < 60) return minutes + " min";
        long hours = minutes / 60;
        if (hours < 48) return hours + " hr";
        return (hours / 24) + " day";
    }

    private static String humanBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        double value = bytes;
        String[] units = {"KiB", "MiB", "GiB", "TiB"};
        int unit = -1;
        do {
            value /= 1024.0;
            unit++;
        } while (value >= 1024.0 && unit < units.length - 1);
        return String.format("%.2f %s", value, units[unit]);
    }

    private record TableStat(String name, long rows, long bytes, Instant oldest, Instant newest) {}
}
