#!/usr/bin/env python3
"""Build a generic, read-only evidence snapshot from the agent SQLite database."""

from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
from typing import Any


def table_exists(database: sqlite3.Connection, name: str) -> bool:
    row = database.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return row is not None


def rows_for_port(database: sqlite3.Connection, port: int) -> list[sqlite3.Row]:
    return list(database.execute(
        """SELECT c.*,p.comm,p.executable_path
             FROM connections c LEFT JOIN processes p ON p.id=c.process_id
            WHERE c.local_port=? OR c.remote_port=? ORDER BY c.last_seen_ns""",
        (port, port)))


def count_for_connections(database: sqlite3.Connection, table: str,
                          connection_ids: list[int], predicate: str = "1=1") -> int:
    if not connection_ids or not table_exists(database, table):
        return 0
    placeholders = ",".join("?" for _ in connection_ids)
    query = f"SELECT count(*) FROM {table} WHERE connection_id IN ({placeholders}) AND {predicate}"
    return int(database.execute(query, connection_ids).fetchone()[0])


def collect_one(database: sqlite3.Connection, contract: dict[str, Any]) -> dict[str, Any]:
    specification = contract.get("evidence", {})
    failures: list[str] = []
    if specification.get("process_only"):
        failures.append("process-only semantic evidence snapshot is unavailable")
        return {"status": "UNSUPPORTED", "failures": failures, "assurance": {}}
    port = specification.get("target_port") or contract.get("detector", {}).get("target_port")
    if not isinstance(port, int):
        return {"status": "UNSUPPORTED", "failures": ["target port is not specified"],
                "assurance": {}}

    rows = rows_for_port(database, port)
    connection_ids = [int(row["id"]) for row in rows]
    if not rows:
        failures.append("no connection evidence for contract target port")
    if rows and not any((row["comm"] or row["executable_path"]) for row in rows):
        failures.append("process attribution unavailable")
    if rows and not any(str(row["direction"]).upper() != "UNKNOWN" for row in rows):
        failures.append("connection direction unavailable")

    if specification.get("file_creation") == "required":
        failures.append("independent file-creation evidence unavailable")
    if specification.get("transfer"):
        transfer_count = count_for_connections(
            database, "connection_transfer_evidence", connection_ids,
            "bytes_sent >= 0 AND bytes_received >= 0 AND source <> ''")
        if transfer_count == 0:
            failures.append("cumulative transfer evidence unavailable")
    if specification.get("retransmissions") == "required":
        retransmissions = count_for_connections(
            database, "transport_samples", connection_ids, "total_retrans > 0")
        if retransmissions == 0:
            failures.append("retransmission evidence unavailable")
    if specification.get("dns") == "required":
        if count_for_connections(database, "connection_name_resolution_evidence", connection_ids) == 0:
            failures.append("name-resolution evidence unavailable")
    if specification.get("dns_negative_control") == "required":
        failures.append("DNS ambiguity negative-control aggregate is not exposed")

    tls_requirement = specification.get("tls_fidelity")
    if tls_requirement:
        exact = count_for_connections(
            database, "connection_tls_session_evidence", connection_ids,
            "correlation_fidelity='EXACT' AND observation_fidelity='EXACT'")
        supporting = count_for_connections(
            database, "connection_tls_session_evidence", connection_ids,
            "correlation_fidelity='SUPPORTING' OR observation_fidelity='SUPPORTING'")
        if exact == 0:
            failures.append("exact application TLS evidence unavailable")
        if tls_requirement == "EXACT_AND_SUPPORTING_DISTINCT" and supporting == 0:
            failures.append("distinct supporting TLS evidence unavailable")

    assurance: dict[str, str] = {}
    expected_assurance = contract.get("assurance", {})
    for field in ("performance", "trust"):
        expected = str(expected_assurance.get(field, "")).upper()
        column = f"{field}_state"
        values = {str(row[column]).upper() for row in rows}
        if expected:
            assurance[field] = expected if expected in values else "MISSING"

    return {"status": "PASS" if not failures else "UNSUPPORTED",
            "connection_ids": connection_ids, "failures": failures,
            "assurance": assurance}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=pathlib.Path, required=True)
    parser.add_argument("--contracts", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    contracts = json.loads(args.contracts.read_text(encoding="utf-8"))["contracts"]
    uri = f"file:{args.database.resolve()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as database:
        database.row_factory = sqlite3.Row
        scenarios = {scenario: collect_one(database, contract)
                     for scenario, contract in contracts.items()}
    args.output.write_text(json.dumps(
        {"schema_version": 1, "scenarios": scenarios}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
