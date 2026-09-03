# Operator CLI

The coordinator exposes small read-only operator commands so routine fleet inspection does not require direct SQL or a temporary Java/Docker process. The `./neta` wrapper talks to the already-running coordinator over its local operator API.

```bash
./neta status
./neta endpoints
./neta endpoint <agent-id-or-name>
./neta findings [limit]
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

## `endpoints` and `endpoint`

`endpoints` prints enrolled agents using coordinator identity and liveness state. `endpoint <id-or-name>` adds enrollment details, last sequence, certificate fingerprint, liveness thresholds, and the retained latest heartbeat payload.

NAP/1 does not yet standardize platform/site heartbeat fields. The views therefore read optional metadata from the heartbeat payload and print `-` when it is unavailable.

## `findings` and `finding`

`findings [N]` prints aggregate finding counts followed by the latest findings, newest first. The default limit is 10 and the maximum is 100. `finding <id>` prints the retained details and payload for one finding.

## Incident grouping v0

Incident v0 is deterministic coordinator-side grouping and requires no new agent payloads. It groups findings only when all of the following are true:

- same enrolled agent,
- same target host and port,
- the existing incident is still `OPEN`, and
- the new finding begins within one hour of the incident's latest member activity.

The one-hour gap is intentionally conservative. Incident v0 does not merge observations across endpoints or across targets. A background coordinator task synchronizes ungrouped findings once per minute by default (`NETA_INCIDENT_SYNC_INTERVAL=PT1M`), and the status/incident operator views also synchronize before rendering.

`incidents [N]` prints recent incidents with agent, target, member finding count, suspicious count and changed count. `incident <id>` prints the incident metadata followed by all member findings.

Incidents are persisted in `incidents` and `incident_findings`; finding rows remain authoritative evidence and membership is traceable.
