# NETA Agent Upgrade Design

## Purpose

Define the first implementation of centrally managed NETA agent upgrades.

The coordinator controls the target version and records upgrade state, while the agent downloads and installs the selected release locally. The coordinator does not initially relay agent binaries.

This keeps the upgrade mechanism narrow and deterministic and avoids turning coordinator control into generic remote execution.

## Goals

- Initiate an agent upgrade from the coordinator/operator interface.
- Keep exact agent version and build information in the coordinator database.
- Resolve the correct immutable GitHub release artifact for the agent platform and architecture.
- Send the selected download URL and expected artifact digest to the agent.
- Let the agent download, verify, stage, activate, health-check, and, if necessary, roll back locally.
- Track upgrade progress and final observed state in the coordinator.
- Preserve a direct local agent upgrade path as a fallback.
- Detect when an agent cannot reach GitHub and report that failure to the coordinator.

## Non-goals for the first implementation

The first implementation does not include:

- coordinator-side binary caching;
- coordinator-to-agent binary streaming;
- full artifact proxying through the coordinator;
- arbitrary remote commands or shell execution;
- replacing the existing agent trust/enrollment model.

Coordinator proxying is a later fallback for agents that cannot directly access the configured GitHub release URL.

## High-level flow

```text
Operator
   |
   | request upgrade to version/build
   v
Coordinator
   |
   | resolve exact release asset for agent OS/architecture
   | persist desired upgrade state
   |
   | upgrade instruction:
   | version/build + immutable URL + SHA-256
   v
Agent
   |
   | HTTPS download from GitHub
   | verify digest/signature metadata
   | stage locally
   | preflight/self-test
   | activate new version
   | restart
   | local health check
   |
   +---- success ----> reconnect/report exact running build
   |
   +---- failure ----> local rollback to previous known-good version
                       reconnect/report rollback result
```

## Coordinator responsibilities

### 1. Store exact observed agent build identity

The coordinator must distinguish the version it requested from the version the agent actually reports running.

Suggested fields on the current agent record:

```text
agent_version
agent_build_id
agent_git_commit
agent_os
agent_arch
agent_artifact_sha256
agent_protocol_version
agent_schema_version
agent_features
build_reported_at
```

The build identity should be reported by the agent during its normal coordinator communication and refreshed when it reconnects after an upgrade.

A version string alone is not sufficient. Two binaries with the same semantic version may have been built from different commits or configurations.

### 2. Resolve available releases

The coordinator should resolve a requested release to an exact artifact for the reporting agent platform and architecture.

For the first implementation, GitHub Releases are the distribution source.

Example release assets:

```text
neta-agent-1.4.0-linux-amd64.tar.gz
neta-agent-1.4.0-linux-arm64.tar.gz
release-manifest.json
release-manifest.sig
```

The release manifest should map platform/architecture to:

```text
version
build_id
git_commit
os
architecture
artifact_name
artifact_url
artifact_sha256
published_at
```

The operator may request `latest` in the future, but the coordinator must resolve it before creating the upgrade request. The persisted request sent to the agent must contain an exact version/build and immutable release asset URL.

The coordinator may persist discovered release metadata in an `agent_releases` table so that release selection and history do not depend on mutable external metadata.

### 3. Persist upgrade requests and state

Suggested `agent_upgrades` fields:

```text
upgrade_id
agent_id

from_version
from_build_id

target_version
target_build_id

artifact_name
artifact_url
artifact_sha256

status

requested_at
delivered_at
download_started_at
install_started_at
confirmed_at
failed_at

failure_code
failure_message
```

The first implementation has one delivery mechanism: direct HTTPS download by the agent from GitHub. A delivery-mode column is therefore optional until coordinator proxying is implemented.

### 4. Operator action

The existing coordinator operator/admin surface should gain an explicit upgrade operation, conceptually:

```text
neta agent upgrade <agent> <version>
```

or the equivalent operator API call.

The coordinator should:

1. resolve the agent;
2. require it to be administratively eligible for upgrade;
3. read its reported OS and architecture;
4. resolve the matching release artifact;
5. persist the exact requested target;
6. audit the upgrade request;
7. expose the pending upgrade instruction to that agent.

### 5. Deliver a typed upgrade instruction

The upgrade request is a dedicated protocol operation, not generic command execution.

Conceptual payload:

```json
{
  "upgrade": {
    "upgrade_id": "...",
    "version": "1.4.0",
    "build_id": "20260905.1",
    "download_url": "https://github.com/.../neta-agent-1.4.0-linux-arm64.tar.gz",
    "sha256": "..."
  }
}
```

The current agent-to-coordinator communication model can be preserved. A pending upgrade can be returned/piggybacked on the agent's normal coordinator interaction rather than requiring a new arbitrary inbound command channel.

### 6. Track progress and failures

The agent should report bounded structured state such as:

```text
DOWNLOAD_STARTED
DOWNLOAD_FAILED
VERIFY_FAILED
STAGED
INSTALLING
LOCAL_HEALTH_FAILED
ROLLED_BACK
```

A direct-download failure should be explicit and useful, for example:

```text
failure_code: DOWNLOAD_UNREACHABLE
failure_message: connection timed out
url_host: github.com
```

This gives the coordinator evidence that direct release delivery does not work for that agent and can later justify coordinator proxying.

### 7. Confirm success from observed runtime identity

The coordinator must not mark an upgrade successful merely because the old agent process reports that installation completed.

A successful upgrade is confirmed only when the restarted agent reconnects and reports the expected target identity, for example:

```text
expected version: 1.4.0
expected build:   20260905.1
expected SHA-256: abc...

reported version: 1.4.0
reported build:   20260905.1
reported SHA-256: abc...
```

Only then should the coordinator mark the upgrade `CONFIRMED`.

This keeps desired state and observed state separate:

```text
Desired:  agent should run 1.4.0 / build 20260905.1
Observed: agent currently reports 1.3.2 / build 20260831.2
```

They converge only after the new process is actually running and reporting.

## Suggested coordinator upgrade state model

```text
REQUESTED
   |
   v
DELIVERED
   |
   v
DOWNLOADING
   |
   v
INSTALLING
   |
   +---------------------------+
   |                           |
   v                           v
reconnect with             failure report
expected build                 |
   |                           v
   v                     FAILED or ROLLED_BACK
CONFIRMED
```

The exact intermediate state names can remain implementation details, but the coordinator must at minimum distinguish:

- requested target;
- instruction delivered;
- failed attempt;
- local rollback;
- confirmed new running build.

## Agent-side installation and rollback model

Rollback is local to the agent machine. The coordinator observes and records the outcome but does not perform the rollback itself.

### Versioned installation layout

The agent should avoid overwriting its running binary in place.

A simple Linux layout is:

```text
/opt/neta-agent/
  current  -> versions/1.3.2/
  previous -> versions/1.3.1/

  versions/
    1.3.1/
      neta-agent
    1.3.2/
      neta-agent
    1.4.0/
      neta-agent
```

The exact directory names may later include the build ID to allow multiple builds of the same semantic version.

### Local upgrade sequence

```text
download target artifact
   |
   v
verify SHA-256/signature
   |
   v
unpack into a new version directory
   |
   v
run local preflight/self-test
   |
   v
remember current version as previous
   |
   v
atomically switch current to new version
   |
   v
restart agent service
```

A small local updater/helper should supervise activation. The process being replaced should not be solely responsible for deciding whether its replacement is healthy.

### Local health confirmation

The new agent should become locally healthy only after important local initialization succeeds, for example:

```text
process starts
configuration loads
local database opens successfully
required probes/subsystems initialize
agent reaches a stable running state
```

Coordinator connectivity is useful confirmation but should not be the only local health criterion. Temporary network loss should not automatically cause a rollback of an otherwise healthy binary.

Therefore distinguish:

```text
LOCAL_HEALTHY
COORDINATOR_CONFIRMED
```

The local updater can wait for a bounded health signal from the new process, such as a local health marker or equivalent mechanism.

### Automatic rollback

If the new version fails to start or does not become locally healthy within the configured timeout:

```text
new agent failed
      |
      v
updater stops failed service
      |
      v
current -> previous known-good version
      |
      v
restart previous version
      |
      v
previous agent reconnects
      |
      v
report UPGRADE_ROLLED_BACK
```

Example result reported to the coordinator:

```text
upgrade_id: ...
target_version: 1.4.0
result: ROLLED_BACK
failure_code: NEW_VERSION_START_FAILED
failure_message: database initialization failed
running_version: 1.3.2
running_build_id: 20260831.2
```

The previous known-good version should not be deleted immediately after a successful upgrade. Retain at least one previous version for rollback, subject to a bounded retention policy.

## Database/schema compatibility requirement

Executable rollback is unsafe if the new binary performs an irreversible local database migration that the previous binary cannot read.

Therefore releases eligible for automatic upgrade must satisfy one of these conditions:

- schema changes remain backward compatible with the previous supported version; or
- a tested rollback migration exists.

For the initial implementation, prefer additive/backward-compatible local schema changes and avoid destructive migrations during automatic upgrades.

## Direct local upgrade fallback

The agent should support a local operator path using the same release resolution, verification, staging, activation, and rollback implementation.

Conceptually:

```text
sudo neta-agent upgrade
sudo neta-agent upgrade --version 1.4.0
```

This is a fallback when coordinator-driven initiation is unavailable. It should not create an independent installation implementation.

After a locally initiated upgrade, the agent still reports its exact running build to the coordinator so fleet inventory remains authoritative.

## Coordinator-proxied delivery: later fallback

Initial delivery is:

```text
Coordinator -- URL/hash --> Agent -- HTTPS --> GitHub Release
```

If the agent cannot reach GitHub, it reports the structured download failure to the coordinator.

A later implementation can add:

```text
Agent --> Coordinator --> GitHub Release
```

The coordinator may then cache or stream only the exact artifact already selected and validated for a particular upgrade request.

Even with proxy delivery, installation remains agent-local. The coordinator should not become a generic remote file writer or command executor.

## Coordinator implementation order

```text
C1  Add agent version/build/platform inventory fields
C2  Accept and persist reported agent build identity
C3  Show exact version/build in operator views
C4  Add GitHub release/manifest resolver
C5  Add persistent agent upgrade requests/state
C6  Add operator upgrade API and CLI command
C7  Deliver pending typed upgrade instruction to agent
C8  Accept bounded progress/failure/rollback reports
C9  Confirm upgrade after reconnect with expected running build
```

Coordinator artifact proxying is deliberately excluded from C1-C9.

## Security invariants

- An upgrade is a narrowly typed operation, not arbitrary remote execution.
- The coordinator selects an exact target release before delivery.
- The agent receives an immutable artifact URL and expected digest.
- The agent verifies the artifact before activation.
- The agent controls local filesystem changes and service restart.
- The coordinator separates requested state from observed running state.
- Upgrade requests and outcomes are auditable.
- A failed GitHub download is reported rather than silently changing delivery behavior.
- Coordinator proxying, when added later, may serve only pre-resolved/validated release artifacts.

## Initial success criteria

The first upgrade milestone is complete when:

1. coordinator operator views show exact running version/build/platform for each reporting agent;
2. the operator can request a specific supported release for an agent;
3. the coordinator resolves and persists the exact GitHub artifact URL and digest;
4. the agent receives that typed upgrade instruction;
5. the agent can report direct-download or installation failures;
6. a successful restarted agent reconnects with the expected build identity and the coordinator marks the request confirmed;
7. a locally failed activation rolls back to the previous known-good version and the coordinator records that rollback;
8. no coordinator binary proxying or generic remote execution is required.
