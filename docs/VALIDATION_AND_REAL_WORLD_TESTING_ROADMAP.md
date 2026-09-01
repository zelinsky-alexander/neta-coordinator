# NETA Validation and Real-World Testing Roadmap

## Purpose

Before approaching Palo Alto, Wazuh, Zeek, firewall, EDR, SIEM, or other security-product communities for external integrations, NETA should first demonstrate that the complete platform is reliable, explainable, scalable, and useful under realistic conditions.

The target state is an always-on deployment containing:

- completed Linux and Windows NETA agents,
- an always-on reliable coordinator,
- the portal,
- several continuously connected demonstration agents,
- repeatable threat-like and benign workloads,
- reproducible evidence and incident scenarios,
- load and endurance validation,
- failure/recovery validation.

The goal is not merely to prove that individual features work. The goal is to establish confidence that NETA can operate continuously as an evidence-driven cybersecurity platform before asking third-party users to contribute real telemetry.

---

## Validation Principles

NETA needs several distinct classes of input. No single dataset or test source is sufficient.

1. **Real benign/background activity** — validates normal behavior, false-positive resistance, baselines, retention, and long-running stability.
2. **Recorded real malicious/threat traffic** — provides deterministic and reproducible regression input.
3. **Controlled live adversary emulation** — validates endpoint-local process, network, DNS, TLS, persistence, and later EDR-style correlations using known ground truth.
4. **Synthetic high-volume evidence** — validates coordinator, storage, protocol, portal, and recovery behavior at scale.

Recorded PCAPs are useful, but they cannot reproduce endpoint-local ground truth such as actual process ownership, PID/socket relationships, registry changes, live file creation, persistence, memory behavior, or response actions. Those require controlled live execution in the NETA test lab.

---

## Lane A — Continuous Benign Real-World Fleet

Run several NETA agents continuously on real machines and realistic workloads for days and weeks.

Recommended demonstration fleet:

- Windows desktop/workstation,
- Windows Server VM,
- Linux workstation or WSL host,
- Linux cloud VM,
- ARM64 Linux cloud VM,
- optional container/Kubernetes host,
- optional dedicated network sensor such as Zeek.

Generate ordinary activity continuously, including:

- web browsing,
- Windows Update and Linux package updates,
- Git/GitHub traffic,
- SSH,
- DNS activity,
- Docker/container traffic,
- development tooling,
- cloud APIs,
- CDNs,
- VPN changes,
- application upgrades,
- certificate and destination changes,
- long-lived and short-lived connections.

### Primary goals

- detect false positives,
- validate baseline learning and changes,
- validate reconnect/restart behavior,
- validate long-running SQLite/storage behavior,
- validate bounded retention,
- validate portal performance during continuous ingestion,
- expose ordinary operating-system and application edge cases,
- validate Linux/Windows semantic parity.

Normal traffic is as important as malicious traffic because a security system that frequently misclassifies legitimate activity is not ready for external users.

---

## Lane B — Recorded Security Datasets and Replay

Build a repeatable replay framework for PCAPs, Zeek logs, flow records, syslog, and later normalized external evidence.

Useful public datasets include:

### Stratosphere IPS datasets

Recommended starting datasets:

- CTU-13 — labeled botnet/C2, normal, and background scenarios,
- CTU-SME-11 — very large labeled benign/malicious flow corpus suitable for throughput testing,
- IoT-23 — malicious and benign IoT scenarios with PCAP and labeled Zeek logs.

### CIC-IDS2017

Useful as a reproducible labeled benchmark containing benign traffic and multiple attack classes. It should primarily be treated as regression and ingestion material rather than proof of modern-threat detection quality.

### What replay should validate

- parser correctness,
- normalized evidence creation,
- DNS/TCP/TLS event processing,
- deterministic rule replay,
- duplicate handling,
- ordering behavior,
- coordinator ingestion throughput,
- portal queries during active ingestion,
- storage growth and retention,
- reproducibility between releases.

Where datasets contain real malware binaries, NETA network testing should normally use PCAP/log artifacts rather than executing those binaries.

---

## Lane C — Controlled Adversary Emulation

Use a dedicated isolated test environment to create live attack-like sequences with known ground truth.

A suitable framework is Apache Caldera (formerly MITRE CALDERA), or equivalent ATT&CK-oriented adversary emulation.

Example lab topology:

```text
                 Adversary-emulation controller
                              |
                     ATT&CK-like actions
                              |
               +--------------+--------------+
               |                             |
        Windows test host              Linux test host
          neta-agent                      neta-agent
               |                             |
               +--------------+--------------+
                              |
                       isolated network
                              |
                    DNS / proxy / Zeek
                              |
                              v
                       NETA Coordinator
                              |
                              v
                           Portal
```

Example scenario chain:

```text
script/process execution
        -> DNS lookup
        -> payload-like download
        -> file creation
        -> child process spawn
        -> outbound C2-like connection
        -> persistence action
```

### Primary goals

- test process-to-network attribution,
- test DNS/process/connection correlation,
- test TLS identity evidence,
- test process-tree correlation,
- test persistence telemetry when implemented,
- test file and executable identity when implemented,
- test response actions when implemented,
- map expected evidence to known scenario ground truth,
- test deterministic incident generation.

Prefer benign emulation of attacker techniques before considering execution of real malware. Any later real-malware testing must be restricted to a disposable, isolated environment with no production credentials and controlled outbound connectivity.

---

## Lane D — Synthetic Coordinator and Fleet Load

Threat datasets should not be the only mechanism used for performance testing.

Create a NETA-native load generator capable of producing structurally valid protocol messages and evidence for large virtual fleets.

Target fleet sizes should include at least:

- 100 agents,
- 1,000 agents,
- 10,000 virtual agents.

Target event rates should include progressively higher levels, for example:

- 50 events/second,
- 1,000 events/second,
- 10,000 events/second,
- higher rates where infrastructure permits.

Generate representative mixtures of:

- agent enrollment/heartbeats,
- network observations,
- DNS evidence,
- TCP samples,
- TLS identities,
- findings,
- corroboration requests/responses,
- external-observer events,
- incident updates,
- evidence retrieval requests.

### Failure and stress scenarios

Test deliberately under:

- network interruption,
- agent reconnect storms,
- coordinator restart,
- portal restart,
- duplicate message delivery,
- delayed delivery,
- out-of-order events,
- clock skew,
- invalid signatures,
- malformed protocol messages,
- slow observers,
- unavailable storage,
- storage pressure,
- retention cleanup while ingesting,
- very large evidence objects,
- simultaneous portal queries and ingestion,
- partial fleet outage.

Measure at least:

- accepted events/sec,
- processing latency,
- queue depth/backpressure,
- database write latency,
- portal/query latency,
- CPU and memory,
- storage growth,
- dropped/rejected events,
- reconnect recovery time,
- duplicate/replay correctness.

---

## Phase Plan

### Phase 1 — Always-On Benign Fleet

Run the coordinator, portal, and several Linux/Windows agents continuously.

Exit criteria:

- stable multi-day operation,
- bounded storage behaves correctly,
- no unexplained data corruption or evidence loss,
- acceptable false-positive behavior,
- reliable reconnect and restart behavior.

### Phase 2 — Replay Framework

Implement deterministic PCAP/log/syslog/evidence replay.

Exit criteria:

- known datasets can be replayed repeatedly,
- equivalent input produces equivalent normalized evidence/verdicts,
- replay is suitable for CI/regression testing.

### Phase 3 — Synthetic Fleet Load

Implement virtual-agent/evidence generation and benchmark increasing fleet sizes and event rates.

Exit criteria:

- capacity limits are measured rather than guessed,
- overload behavior is bounded and observable,
- no silent evidence loss,
- recovery behavior is tested.

### Phase 4 — Adversary Emulation

Add isolated Windows/Linux ATT&CK-style scenarios.

Exit criteria:

- scenario ground truth is documented,
- expected NETA evidence is defined,
- correlations are deterministic and reproducible,
- detection misses and false positives are recorded as test results.

### Phase 5 — Mixed Realistic Validation

Run all lanes together:

- benign real traffic,
- adversary-emulation scenarios,
- external observer/log replay,
- synthetic load,
- network and service failures.

This phase should test the system while portal users actively query evidence and incidents.

Exit criteria:

- acceptable reliability under mixed load,
- expected incidents remain explainable,
- contradictory evidence remains visible,
- coordinator and portal remain usable,
- no silent data loss or trust/fidelity inflation.

### Phase 6 — Endurance / Soak Testing

Run sustained 72-hour and then 7-day tests.

Monitor:

- memory growth/leaks,
- storage growth and cleanup,
- CPU trends,
- queue accumulation,
- stale sessions,
- reconnect behavior,
- database health,
- portal latency,
- evidence consistency,
- agent/coordinator clock drift effects.

---

## External Integration Readiness Gate

Do not approach Palo Alto, Wazuh, Zeek, EDR/SIEM, or similar communities merely with an architectural proposal.

Before requesting external telemetry or community participation, NETA should be able to demonstrate:

1. an always-on public/reachable coordinator deployment,
2. an operational portal,
3. several continuously connected real agents,
4. Linux and Windows support at the intended milestone level,
5. documented reproducible threat-like scenarios,
6. replayable public datasets,
7. measured load/capacity results,
8. multi-day endurance results,
9. deterministic evidence-to-verdict explanations,
10. recovery from restart/network/failure conditions,
11. clear handling of provenance, fidelity, contradiction, and trust,
12. a concrete demonstration of why third-party telemetry becomes more useful when correlated inside NETA.

Only after this gate should the project begin actively asking third-party security-product communities to send or integrate real operational telemetry.

---

## Desired Demonstration

A convincing public demo should show one scenario from end to end:

```text
real endpoint behavior
      |
      +-- native NETA endpoint evidence
      |
      +-- DNS/network evidence
      |
      +-- replayed or live external observer evidence
      |
      v
NETA Coordinator
      |
      +-- normalization
      +-- provenance
      +-- correlation
      +-- corroboration / contradiction
      +-- deterministic rules
      |
      v
Portal incident
```

The portal should make it possible to answer:

- What happened?
- Which endpoint/entity was involved?
- Which observers saw it?
- What evidence supports the conclusion?
- What evidence contradicts it?
- How strong is each observation?
- Can the same conclusion be reproduced from retained evidence?

That demonstration is the bridge between NETA as a technically promising project and NETA as a platform that external security users can reasonably trust with real evidence feeds.
