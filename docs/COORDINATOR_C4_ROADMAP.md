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
| C4.7 | Certificate lifecycle and rotation | DONE |

## C4.7 — Certificate lifecycle and rotation

### Implemented policy

- New NETA-issued agent certificates default to **90 days** (`NETA_ENROLLMENT_CERTIFICATE_TTL=P90D`).
- Warning threshold defaults to **30 days** (`NETA_CERTIFICATE_WARNING_WINDOW=P30D`).
- Critical threshold defaults to **7 days** (`NETA_CERTIFICATE_CRITICAL_WINDOW=P7D`).
- Expired certificates are rejected by explicit coordinator ingestion policy in addition to normal TLS/X.509 validation.
- Revocation remains independent and immediately disables an enrolled agent.

### Lifecycle persistence

Flyway V5 adds active certificate validity metadata to `agents` and an `agent_certificate_history` table. Newly enrolled certificates persist their actual X.509 `notBefore` and `notAfter` values. Existing pre-C4.7 agents are automatically backfilled from the authenticated peer X.509 certificate on their next accepted mTLS message.

The coordinator records:

- active SHA-256 fingerprint,
- `notBefore`,
- `notAfter`,
- registration time,
- last rotation time,
- active/retired certificate history,
- rotation reason.

Private keys are never stored by the coordinator.

### Operator visibility

```text
./neta certificates
./neta certificates --expiring 30d
./neta certificate <agent-id-or-name>
./neta agent <agent-id-or-name>
./neta status
```

Lifecycle states are `VALID`, `EXPIRING`, `CRITICAL`, `EXPIRED`, and temporarily `UNKNOWN` until a pre-C4.7 enrollment sends an authenticated message and its validity dates are backfilled.

`./neta status` includes fleet certificate counts. Agent administration detail appends certificate lifecycle and certificate-history information.

### Health checks

`deploy/health-check.sh` is read-only and now:

- verifies certificate lifecycle operator access,
- warns for `EXPIRING`, `CRITICAL`, or temporarily `UNKNOWN` lifecycle state,
- fails if an enrolled active certificate is `EXPIRED`,
- never rotates or revokes automatically.

### Rotation flow

C4.7 uses the already configured NETA fleet enrollment issuer rather than inventing a second CA path. Rotation is operator-authorized with `NETA_OPERATOR_ADMIN_TOKEN`, requires a new PKCS#10 CSR and explicit `--yes`, and preserves the same `AgentId`.

```text
agent creates new private key + CSR
        |
        v
./neta certificate rotate <agent> --csr new.csr --out new-chain.pem --reason ... --yes
        |
        v
coordinator validates CSR and issues new client certificate
        |
        +-- retires old fingerprint in certificate history
        +-- atomically activates new fingerprint/validity
        +-- writes AGENT_CERTIFICATE_ROTATED audit event
        v
operator installs new certificate chain with the new endpoint-local private key
```

After coordinator activation, the old certificate fingerprint is rejected by normal ingestion fingerprint matching. The returned file contains the replacement certificate chain only; the private key remains on the endpoint that generated the CSR.

The operator-assisted authorization is intentionally conservative for this milestone. A later unattended renewal flow can require proof of possession of the currently active agent identity before automatic issuance.

### Recovery boundary

Rotation is an explicit operator action. Because activating the replacement fingerprint immediately retires the old identity, operators should generate and securely retain the new private key/CSR before rotation and install the returned chain immediately. If installation fails, the same protected rotation mechanism can issue another replacement CSR; revocation/reactivation remains separate from certificate replacement.

## Boundary after C4

C4 is complete as the coordinator fleet-administration and local-investigation phase. Cross-agent reasoning belongs to the next coordinator phase, including persisted corroboration requests, fan-out/lifecycle, responses, and HOST_LOCAL / SITE_LOCAL / REGIONAL / GLOBAL reasoning.
