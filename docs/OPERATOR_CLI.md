# Operator CLI

The coordinator exposes small read-only operator commands so routine fleet inspection does not require direct SQL or a temporary Java/Docker process. The `./neta` wrapper talks to the already-running coordinator over its local operator API.

```bash
./neta status
./neta storage
./neta endpoints
./neta endpoints --status online
./neta endpoint <agent-id-or-name>
./neta endpoint-history <agent-id-or-name> [--last 24h] [--type heartbeat] [--limit 100]
./neta findings [filters]
./neta findings-summary
./neta finding <finding-id>
./neta incidents [limit]
./neta incident <incident-id>
```

## `status`

Prints the fleet-level operational summary: endpoint liveness, finding counts, incident counts, last ingestion age, grouping window, and whether the coordinator is enforcing mTLS.

Endpoint liveness defaults are:

- `ONLINE`: last accepted agent message is at most 7 minutes old.
- `STALE`: more than 7 minutes but at most 15 minutes old.
- `OFFLINE`: more than 15 minutes old.
- `NEVER_SEEN`: enrolled but no accepted message has been received.
- `REVOKED`: enrollment is revoked.

The thresholds can be overridden with `NETA_AGENT_ONLINE_THRESHOLD` and `NETA_AGENT_OFFLINE_THRESHOLD`.

## Storage and retention status (C4.5)

`storage` prints PostgreSQL database size, row counts and PostgreSQL relation sizes for the coordinator's major tables, oldest/newest retained timestamps where meaningful, and the active bounded-storage configuration.

```bash
./neta storage
```

It reports the current heartbeat retention mode, heartbeat audit mode, protocol retention, audit/contact-history retention, and cleanup interval. The retention-window section compares the configured windows with the observed oldest rows for `protocol_messages`, accepted-message audit rows, compact endpoint contact history, and consumed enrollment tokens.

The command is read-only. It does not run cleanup or VACUUM and does not impose a new database-size cap. PostgreSQL `pg_database_size` and `pg_total_relation_size` are used for storage accounting.

The coordinator health check also verifies that the storage/retention operator view is reachable and exposes its retention configuration:

```bash
sudo ./deploy/health-check.sh
```

## Endpoint filtering

Filter by computed liveness:

```bash
./neta endpoints --status online
./neta endpoints --status stale
./neta endpoints --status offline
./neta endpoints --status revoked
./neta endpoints --status never_seen
```

## Endpoint detail and history

`endpoint <id-or-name>` prints enrollment details, last sequence, certificate fingerprint, liveness thresholds, the retained latest heartbeat payload, and recent findings/incidents.

`endpoint-history` uses a compact bounded contact-history table. Every accepted agent message contributes only agent ID, message type, sequence, message ID, and coordinator receipt time. Full heartbeat payloads are not duplicated.

```bash
./neta endpoint-history wsl-agent-1
./neta endpoint-history wsl-agent-1 --last 24h
./neta endpoint-history wsl-agent-1 --last 7d --limit 200
./neta endpoint-history wsl-agent-1 --type heartbeat
```

Supported `--last` values include `30m`, `24h`, `7d`, and ISO-8601 durations such as `PT12H`. Contact history is retained according to `NETA_ACCEPTED_AUDIT_RETENTION` (default `P30D`).

## Finding investigation and search (C4.3)

`findings` is a combinable read-only search command. Supported filters include agent, Trust verdict, Performance verdict, finding status, target, recency, sorting, offset, and limit.

```bash
./neta findings --agent wsl-agent-1
./neta findings --trust changed
./neta findings --trust suspicious --since 24h
./neta findings --performance insufficient_evidence
./neta findings --status active
./neta findings --target 127.0.0.1:9443
./neta findings --agent wsl-agent-1 --trust changed --since 7d
./neta findings --sort occurrences --order desc --limit 25
./neta findings --limit 25 --offset 25
```

For compatibility, `./neta findings 25` is still accepted as a shorthand for `--limit 25`.

`--since` accepts compact values such as `30m`, `24h`, `7d`, or ISO-8601 durations such as `PT12H`. Supported sort values are `last_seen`, `first_seen`, `occurrences`, `agent`, and `target`. The default is newest last-seen first.

Search output includes the incident ID when the finding is currently grouped, providing direct navigation from finding search into Incident v0.

`finding <id>` now leads with a compact analyst view before raw retained material: agent and incident linkage, target, state, occurrence count, first/last seen, Trust and Performance assessment, observed changes, evidence root, rule set, and then the raw payload.

```bash
./neta finding FINDING-CONN-167-22c85e3784dc
./neta incident INCIDENT-...
```

`findings-summary` provides a quick aggregate investigation view:

```bash
./neta findings-summary
```

It reports total/active findings, Trust distribution, Performance distribution, top targets, and the endpoints with the most retained findings.

C4.3 remains read-only. Acknowledge/close/assign/comment workflow state is intentionally deferred until analyst authorization and incident lifecycle semantics are defined.

## Incident grouping v0

Incident v0 is deterministic coordinator-side grouping and requires no new agent payloads. It groups findings only when all of the following are true:

- same enrolled agent,
- same target host and port,
- the existing incident is still `OPEN`, and
- the new finding begins within one hour of the incident's latest member activity.

The one-hour gap is intentionally conservative. Incident v0 does not merge observations across endpoints or across targets. A background coordinator task synchronizes ungrouped findings once per minute by default (`NETA_INCIDENT_SYNC_INTERVAL=PT1M`), and the status/incident operator views also synchronize before rendering.

`incidents [N]` prints recent incidents with agent, target, member finding count, suspicious count and changed count. `incident <id>` prints incident metadata followed by all member findings.

Incidents are persisted in `incidents` and `incident_findings`; finding rows remain authoritative evidence and membership is traceable.

NAP/1 does not yet standardize platform/site heartbeat fields. Endpoint views therefore read optional metadata from the heartbeat payload and print `-` when unavailable.
