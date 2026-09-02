# Operator CLI

The coordinator exposes small read-only operator commands so routine fleet inspection does not require direct SQL.

Build the application first:

```bash
mvn package
```

Run commands with the same datasource environment used by the coordinator service:

```bash
java -jar target/neta-coordinator-0.1.0-SNAPSHOT.jar endpoints
java -jar target/neta-coordinator-0.1.0-SNAPSHOT.jar findings
java -jar target/neta-coordinator-0.1.0-SNAPSHOT.jar findings 25
java -jar target/neta-coordinator-0.1.0-SNAPSHOT.jar help
```

## `endpoints`

Prints enrolled agents using the coordinator's authoritative identity and last-seen state:

```text
AGENT                    PLATFORM           SITE               STATUS     LAST SEEN
------------------------------------------------------------------------------------------
desktop-wsl              Linux/x64          Israel             ONLINE     3 sec
aws-eu-arm               Linux/arm64        Europe             ONLINE     8 sec
```

`ONLINE` currently means an ACTIVE enrolled agent was seen within the last two minutes. Revoked agents are shown as `REVOKED`; ACTIVE agents outside the freshness window are `OFFLINE`.

NAP/1 does not yet standardize platform/site heartbeat fields. The command therefore reads optional metadata from the retained heartbeat payload and prints `-` when it is unavailable. Agent identity, enrollment status, and `last_seen_at` do not depend on those optional fields.

## `findings [N]`

Prints aggregate finding counts followed by the latest findings, newest first. The default limit is 10 and the maximum is 100.

The table includes agent, target, Trust and Performance verdicts, deduplicated occurrence count, finding status, and finding ID.

These commands are read-only and do not change coordinator state.
