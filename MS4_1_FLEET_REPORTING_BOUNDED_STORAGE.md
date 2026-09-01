# MS4.1 — Fleet Reporting and Bounded Coordinator Storage

This coordinator milestone bounds routine NAP/1 storage while preserving durable fleet state and important findings.

## Heartbeats are current state

Default behavior does not retain every heartbeat as a protocol or audit row. A valid heartbeat still passes normal NAP/1 freshness/sequence checks and mTLS AgentId binding, then updates:

- `agents.last_sequence`
- `agents.last_seen_at`
- `agents.last_heartbeat_payload`

Raw heartbeat retention and heartbeat audit rows can be explicitly enabled for lab/debug use.

## Findings are logical incidents

Flyway V2 adds `finding_key`, `first_seen`, `last_seen`, `occurrence_count`, and `status`. Repeated announcements of the same logical issue from the same agent upsert the existing row and increase `occurrence_count` instead of creating unlimited semantic finding rows.

## Bounded ingress journal

Non-heartbeat `protocol_messages` remain useful as a recent protocol/debug journal but are not permanent business storage. A scheduled cleanup removes them after the configured TTL. Routine `MESSAGE_ACCEPTED` audit rows have a separate TTL. Durable agent identity and finding state are not removed by this routine cleanup.

Default settings:

```text
NETA_RETAIN_HEARTBEATS=false
NETA_AUDIT_HEARTBEATS=false
NETA_PROTOCOL_RETENTION=P7D
NETA_ACCEPTED_AUDIT_RETENTION=P30D
NETA_STORAGE_CLEANUP_INTERVAL=PT1H
```

The implementation remains PostgreSQL-only; no queue, Redis, Kafka, or alternate data store is introduced by MS4.1.
