# NETA Coordinator

**NETA Coordinator is the trusted orchestration and correlation layer for a distributed NETA network-assurance fleet.**

This repository contains the coordinator-side implementation of NAP/1. It is intentionally a modular monolith: C++ `neta-agent` endpoints remain measurement engines, while this Java service owns fleet identity, ingestion, replay/freshness checks, correlation persistence, corroboration state, retention/audit, and the central PostgreSQL store.

## First-version scope

Implemented now:

- Java 21 LTS + Spring Boot 3.5.x;
- PostgreSQL schema managed by Flyway;
- one-time bootstrap enrollment tokens stored only as SHA-256 hashes;
- stable coordinator-assigned `AgentId`;
- enrolled certificate fingerprint binding;
- NAP/1 envelope parsing and structural validation;
- expiry, clock-skew and maximum-message-lifetime policy;
- per-agent monotonic sequence and message replay protection;
- compact `FindingAnnouncement` persistence and target indexing;
- `CorroborationResponse` persistence only for known requests;
- `EvidenceSummary` persistence;
- audit events;
- optional application-level TLS 1.3/mTLS profile;
- health endpoint and CI unit tests.

Deliberately **not** claimed as complete yet:

- C4.7 certificate lifecycle/expiry tracking and secure rotation (planned in `docs/COORDINATOR_C4_ROADMAP.md`);
- coordinator CA/certificate issuance lifecycle beyond current enrolled-fingerprint trust and C4.6 revocation;
- canonical NAP/1 object serialization;
- cryptographic verification of retained object signatures or `payload_hash` values;
- coordinator-side corroboration selection/fan-out scheduler;
- evidence-bundle request/transfer;
- fleet verdict/correlation rules;
- redundant coordinator operation.

NAP/1 requires an unambiguous canonical representation before signed objects can be verified. Until that protocol detail is fixed, this service requires signature metadata but does not falsely treat it as cryptographically verified. This first version is therefore a development foundation, not a production-ready trust authority.

## Architecture

```text
neta-agent (C++20)
        |
        | NAP/1 HTTPS / TLS 1.3
        | mTLS for normal agent messages
        v
+-------------------------------+
| neta-coordinator (Java 21)    |
| enrollment | protocol         |
| ingestion  | identity         |
| findings   | corroboration    |
| evidence   | audit            |
+---------------+---------------+
                |
                v
           PostgreSQL
```

Detailed endpoint evidence remains local by default. The central store receives compact findings, summaries, corroborations, provenance, and selected evidence only when later protocol phases explicitly request it.

## Run locally

Prerequisites: Java 21, Maven 3.6.3+, Docker/Compose.

```bash
docker compose up -d postgres
export NETA_BOOTSTRAP_ENROLLMENT_TOKEN='replace-with-a-long-random-token'
mvn spring-boot:run
```

The service listens on `http://localhost:8080` for development. Secure message ingestion defaults to requiring a client certificate. For a local-only API smoke test without TLS, explicitly disable that check:

```bash
export NETA_REQUIRE_CLIENT_CERTIFICATE=false
```

Do not use that override in production.

Health:

```bash
curl http://localhost:8080/actuator/health
```

## Operator CLI

When the coordinator is already running, use the lightweight host-side wrapper instead of starting a one-off Java container:

```bash
./neta endpoints
./neta findings
./neta findings 25
```

The wrapper talks to the running coordinator at `http://127.0.0.1:8080` by default, so it does not require Docker socket access, does not start another JVM, and does not wait for Compose dependency health checks. Override the address with `NETA_COORDINATOR_URL` when needed. For HTTPS/mTLS deployments, `NETA_OPERATOR_CA`, `NETA_OPERATOR_CERT`, and `NETA_OPERATOR_KEY` are supported.

The backing read-only endpoints are:

```text
GET /api/v1/operator/endpoints
GET /api/v1/operator/findings?limit=10
```

Keep the coordinator bound to loopback unless these operator endpoints are placed behind an appropriate authenticated management boundary.

## Enrollment

Enrollment uses a configured one-time token and registers an already provisioned agent certificate fingerprint. Automatic certificate issuance is intentionally deferred because NAP/1 does not yet specify the CA issuance API. Certificate expiration tracking and secure rotation are explicitly planned as C4.7; see `docs/COORDINATOR_C4_ROADMAP.md`.

```bash
curl -X POST http://localhost:8080/api/v1/enrollment \
  -H 'Content-Type: application/json' \
  -d '{
    "fleetId":"fleet-dev",
    "token":"replace-with-a-long-random-token",
    "displayName":"wsl-israel",
    "certificateSha256":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }'
```

The token is consumed transactionally and cannot be reused.

## TLS 1.3 / mTLS

The `mtls` Spring profile enables TLS 1.3 and requests client certificates while still permitting token-based initial enrollment on the same listener. Supply PKCS#12 server and trust stores:

```bash
export SPRING_PROFILES_ACTIVE=mtls
export NETA_TLS_KEY_STORE=/etc/neta/coordinator.p12
export NETA_TLS_KEY_STORE_PASSWORD='...'
export NETA_TLS_TRUST_STORE=/etc/neta/fleet-trust.p12
export NETA_TLS_TRUST_STORE_PASSWORD='...'
mvn spring-boot:run
```

Normal `/api/v1/messages` ingestion verifies that the presented peer certificate fingerprint matches the certificate fingerprint bound to the enrolled `AgentId`.

## Database model

The initial schema separates:

- `agents` and `enrollment_tokens`;
- immutable accepted `protocol_messages`;
- indexed `findings`;
- `corroboration_requests` / `corroboration_responses`;
- `evidence_summaries`;
- `audit_events`.

PostgreSQL uniqueness constraints enforce per-agent message-id and sequence replay protection at the storage boundary as well as in service logic.

## Dependencies and licensing

Project license: Apache-2.0.

- Spring Boot / Spring Framework — Apache-2.0 — service framework, HTTP, JDBC, validation, actuator; actively maintained; no material licensing concern identified.
- PostgreSQL JDBC — BSD-2-Clause — database driver; actively maintained; no material licensing concern identified.
- Flyway Community/core — Apache-2.0 components used for migrations; actively maintained; commercial-only Flyway features are not required.

See `THIRD_PARTY_NOTICES.md`. Dependency/license/security review should be repeated before publishing a binary release; generated project code is not a substitute for normal legal or similarity review.

## Build and test

```bash
mvn verify
```
