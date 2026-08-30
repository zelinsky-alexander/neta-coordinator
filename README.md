# NETA Coordinator

NETA Coordinator is the trusted orchestration and correlation layer for a distributed NETA network-assurance fleet.

This repository contains the coordinator-side implementation of the NETA Agent Communication Protocol (NAP/1). The implementation is evidence-first: agents publish compact observations and provenance, while detailed endpoint evidence remains local unless explicitly requested.

The first implementation is being built as a Java modular monolith backed by PostgreSQL.
