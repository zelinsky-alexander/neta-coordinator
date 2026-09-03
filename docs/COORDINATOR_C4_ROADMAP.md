# NETA Coordinator C4 Roadmap

## Purpose

C4 turns the coordinator from a basic ingestion service into an operator-usable fleet-management and investigation plane while keeping endpoint evidence collection in `neta-agent`.

## Status

| Item | Capability | Status |
|---|---|---|
| C4.1 | Fleet status/dashboard | DONE |
| C4.2 | Endpoint history + filtering | DONE |
| C4.3 | Finding investigation/search | DONE |
| C4.4 | Incident grouping v0 | DONE |
| C4.5 | Storage/retention status | DONE |
| C4.6 | Agent administration/revocation | DONE |
| C4.7 | Certificate lifecycle and rotation | PLANNED |

## C4.7 — Certificate lifecycle and rotation

### Goal

Bound the lifetime of agent credentials, make upcoming certificate expiry visible to operators, and support safe certificate replacement without changing the stable NETA `AgentId`.

Expiration and revocation solve different problems and both are required:

- **expiration** limits how long a credential remains usable by default;
- **revocation** immediately removes trust when an identity or private key is suspected to be compromised.

### Initial policy

- Default agent-certificate lifetime target: **90 days**.
- Coordinator warning threshold: **30 days before expiry**.
- Strong/critical warning threshold: **7 days before expiry**.
- An expired certificate must not be accepted for normal agent ingestion.
- Successful rotation should retire the previous certificate identity rather than leaving both trusted indefinitely.
- Initial rotation may be explicit/operator-assisted; automatic renewal should only be enabled after the rotation flow is proven reliable.

The lifetime and warning thresholds should be configurable rather than permanently hard-coded.

### Coordinator data model

Track certificate lifecycle metadata for each enrolled agent, at minimum:

- certificate SHA-256 fingerprint,
- certificate `notBefore`,
- certificate `notAfter`,
- issuance/registration time,
- most recent rotation time,
- lifecycle status.

A later implementation may normalize certificates into a separate certificate-history table so prior fingerprints and rotation events remain auditable while the active certificate remains unambiguous.

### Operator visibility

Planned operator views:

```text
./neta certificates
./neta certificates --expiring 30d
./neta agent <agent-id-or-name>
./neta status
```

Expected fleet summary shape:

```text
Certificates
  Valid          N
  Expiring       N
  Critical       N
  Expired        N
```

Agent detail should show the active fingerprint, validity interval, remaining lifetime, and most recent rotation event.

### Health and operational checks

`deploy/health-check.sh` should warn when an active agent certificate is within the configured warning window and fail or prominently report any active enrollment whose certificate is already expired.

The health check must remain read-only and must never rotate or revoke a certificate automatically.

### Secure rotation flow

The rotation design must preserve the stable NETA `AgentId` while proving possession of an already trusted identity.

Conceptual flow:

```text
currently trusted agent certificate
            |
            | authenticated rotation request / authorization
            v
Coordinator or fleet CA validates current identity
            |
            | issues or authorizes replacement certificate
            v
agent installs replacement certificate + private key
            |
            | reconnects and proves possession
            v
Coordinator atomically activates new fingerprint
            |
            v
previous certificate is retired/rejected
```

Requirements:

1. Rotation must not be authorized solely by knowledge of an `AgentId`.
2. The existing trusted identity, an explicit operator authorization, or another strong fleet-management credential must authorize the transition.
3. The new certificate must be validated before the old certificate is retired.
4. Rotation events must be written to `audit_events` with old/new fingerprints and reason/source metadata, without storing private keys.
5. Failure during rotation must not leave the endpoint permanently unable to recover; an explicit bounded recovery path must exist.
6. Private keys remain endpoint-local or CA-managed and are never stored in coordinator application logs or normal database rows.

### Certificate authority boundary

C4.7 does not require the coordinator itself to become a general-purpose CA. The implementation should keep issuance and lifecycle-policy responsibilities separable so NETA can later use:

- the existing fleet CA tooling,
- an external/private PKI,
- or a dedicated NETA certificate service.

The coordinator remains responsible for deciding which certificate identity is trusted for a given NETA agent and for enforcing lifecycle state during ingestion.

### Exit criteria

C4.7 is complete when:

- certificate validity dates are recorded for enrolled agents;
- operator views clearly show valid/expiring/expired state;
- configurable 30-day and 7-day warning behavior exists;
- expired certificates cannot successfully authenticate normal agent ingestion;
- a documented rotation flow replaces an agent certificate without changing `AgentId`;
- the previous certificate is rejected after successful rotation;
- rotation and lifecycle changes are auditable;
- health checks report expiry risk without mutating fleet state;
- recovery behavior is tested for interrupted/failed rotation.

## Boundary after C4

C4 remains primarily fleet administration and local coordinator investigation. Cross-agent reasoning belongs to the next coordinator phase, including persisted corroboration requests, fan-out/lifecycle, responses, and HOST_LOCAL / SITE_LOCAL / REGIONAL / GLOBAL reasoning.
