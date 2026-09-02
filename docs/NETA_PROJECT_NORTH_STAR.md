# NETA Project North-Star Goal

## Core Objective

The major goal of the NETA project is to demonstrate to the professional software and cybersecurity world that, today, a single experienced and capable programmer / technical lead, using modern AI tools effectively, can independently design, build, test, deploy, operate, and evolve a small but genuinely capable Endpoint Detection and Response (EDR) system.

The proof should not merely be:

> "I built an EDR-like agent with AI."

The stronger and more credible claim is:

> **One experienced engineer, using modern AI-assisted development, can design, implement, test, ship, operate, and evolve a small but credible endpoint detection and response system without a traditional engineering team.**

---

## What NETA Must Demonstrate

For this claim to be credible to security engineers, architects, hiring managers, potential users, and other experienced technical professionals, NETA must demonstrate several things at the same time.

### 1. Real Endpoint Capability

NETA should provide meaningful endpoint-security functionality rather than only a networking or telemetry prototype.

Important capabilities include:

- process and network observation;
- inbound and outbound connection attribution;
- TCP and route evidence;
- DNS attribution;
- TLS peer identity;
- connection and process history;
- evidence collection;
- trusted baselines;
- anomaly or policy deviation detection;
- investigation workflows;
- threat-emulation validation;
- eventually, safe response actions.

The goal is not to reproduce every capability of a large commercial EDR, but to implement a coherent and useful subset deeply enough that experienced practitioners recognize it as a real endpoint-security system.

### 2. Engineering Quality

NETA must demonstrate professional software-engineering quality.

That includes:

- clear architecture;
- maintainable code;
- automated tests;
- CI;
- storage migrations;
- bounded evidence and database growth;
- failure handling;
- diagnostics;
- performance measurements;
- security of the agent itself;
- platform portability;
- documented design decisions.

A technically interesting prototype is not sufficient. The project should look like software that could realistically be maintained and operated.

### 3. Operational Reality

The system should run continuously on real machines.

NETA should demonstrate that it can:

- survive restarts;
- preserve useful history;
- recover cleanly from failures;
- manage storage limits;
- upgrade safely;
- expose useful operational status;
- run on remote systems;
- support multiple endpoints;
- remain usable over long-running deployments.

Operational reliability is one of the strongest signals separating a real system from a demonstration.

### 4. Security Credibility

Threat detection should be demonstrated against realistic behaviors.

The Threat Emulation Lab should be used to prove that known malicious or suspicious activity produces meaningful evidence, detections, or investigation signals.

Over time, demonstrations should cover behaviors such as:

- suspicious process execution;
- unusual outbound communication;
- suspicious inbound exposure;
- unexpected TLS identities;
- DNS anomalies;
- persistence-related activity;
- privilege or identity changes;
- suspicious process/network relationships;
- deviation from previously accepted baselines.

The emphasis should be on evidence that an analyst could actually use.

### 5. Scale Appropriate to the Claim

NETA does not need to compete directly with CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, or similar platforms operating across millions of machines.

That is not the thesis being tested.

A credible target is a small EDR capable of operating across:

- a developer lab;
- a home or small-business environment;
- a small server fleet;
- dozens of endpoints;
- eventually perhaps hundreds of endpoints.

If the architecture supports further scaling, that is valuable, but proving useful small-scale operation is sufficient for the central project claim.

### 6. AI Leverage Must Be Visible

A major part of the project is demonstrating what AI changes in software-engineering economics.

The project should therefore make AI-assisted development visible in areas such as:

- architecture exploration;
- implementation;
- debugging;
- automated testing;
- code review;
- threat modeling;
- documentation;
- cross-platform porting;
- operational troubleshooting;
- log and evidence analysis;
- research;
- design iteration.

The important point is not that AI independently built NETA.

The important point is that AI significantly increases the productive capacity of one experienced engineer.

### 7. Human Engineering Ownership Must Remain Clear

AI is the force multiplier.

The engineer remains responsible for:

- system architecture;
- requirements;
- prioritization;
- technical judgment;
- security boundaries;
- validation;
- testing;
- acceptance of generated changes;
- operational decisions;
- final responsibility for the system.

This distinction is important to the credibility of the project.

NETA should demonstrate **AI-augmented engineering**, not uncontrolled autonomous code generation.

---

## The Public Demonstration

The eventual demonstration should communicate a complete system story:

> **1 engineer → NETA management/control layer → Linux and Windows agents → real endpoints → collected evidence → behavioral detections → threat-emulation event → investigation → response**

This is much stronger than presenting an isolated list of implemented features.

Supporting evidence can include:

- repository history;
- architecture documents;
- milestone history;
- CI results;
- automated test counts;
- supported operating systems;
- installation and deployment procedures;
- performance measurements;
- CPU and memory usage;
- storage consumption;
- detection scenarios;
- threat-emulation results;
- investigation examples;
- operational uptime;
- multi-host demonstrations;
- development chronology.

A short engineering journal could additionally document where AI materially reduced implementation time, debugging time, or research effort.

---

## Roadmap Principle

The project roadmap should prioritize features that make NETA more convincingly operational as an EDR rather than features that merely increase technical sophistication.

For example, these may provide more proof of the core thesis:

- polished multi-host deployment;
- central evidence and endpoint visibility;
- Linux plus Windows endpoint support;
- trustworthy process/network attribution;
- a credible threat-emulation demonstration;
- persistent investigation history;
- baseline and anomaly workflows;
- reliable bounded storage;
- one or more safe response actions.

These may be more valuable than adding many highly specialized telemetry fields that do not materially improve the end-to-end demonstration.

---

## North-Star Decision Criterion

For future milestones, architecture choices, and feature prioritization, use the following question:

> **Would this milestone make an experienced security engineer more willing to call NETA a real small EDR rather than an impressive networking prototype?**

If the answer is yes, the work is strongly aligned with the central project goal.

---

## Definition of Success

NETA succeeds when a technically experienced observer can reasonably conclude all of the following:

1. This is a real working endpoint-security system.
2. It collects and preserves useful endpoint evidence.
3. It can identify meaningful suspicious behavior.
4. It can support investigation of endpoint activity.
5. It operates reliably across real machines.
6. It has credible engineering quality.
7. It was built and operated primarily by one experienced engineer.
8. Modern AI tooling materially enabled that engineer to accomplish work that historically would have required a larger team.

That conclusion is the central proof the NETA project is intended to produce.
