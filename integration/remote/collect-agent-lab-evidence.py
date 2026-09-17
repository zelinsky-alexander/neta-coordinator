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
        """SELECT c.id,c.target_host,c.local_ip,c.local_port,c.remote_ip,c.remote_port,
                  c.direction,c.lifecycle_state,c.first_seen_ns,c.last_seen_ns,
                  c.performance_state,c.trust_state,p.comm,p.executable_path
             FROM connections c LEFT JOIN processes p ON p.id=c.process_id
            WHERE c.local_port=? OR c.remote_port=? ORDER BY c.last_seen_ns""",
        (port, port)))


def query_rows(database: sqlite3.Connection, query: str,
               parameters: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in database.execute(query, parameters)]


def connection_diagnostics(database: sqlite3.Connection,
                           rows: list[sqlite3.Row]) -> dict[str, Any]:
    connection_ids = [int(row["id"]) for row in rows]
    if not connection_ids:
        return {"connections": [], "transport": [], "transfer": [], "resolver": [],
                "tls": [], "verdicts": []}
    placeholders = ",".join("?" for _ in connection_ids)
    parameters = tuple(connection_ids)
    diagnostics: dict[str, Any] = {
        "connections": [dict(row) for row in rows],
        "transport": query_rows(database, f"""
            SELECT connection_id,count(*) AS sample_count,
                   sum(CASE WHEN rtt_us>0 THEN 1 ELSE 0 END) AS nonzero_rtt_samples,
                   min(total_retrans) AS minimum_total_retrans,
                   max(total_retrans) AS maximum_total_retrans,
                   max(total_retrans)-min(total_retrans) AS retransmission_delta,
                   max(rtt_us) AS maximum_rtt_us,max(rttvar_us) AS maximum_rttvar_us
              FROM transport_samples WHERE connection_id IN ({placeholders})
             GROUP BY connection_id ORDER BY connection_id
        """, parameters),
        "transfer": [],
        "resolver": [],
        "tls": [],
        "verdicts": [],
    }
    if table_exists(database, "connection_transfer_evidence"):
        diagnostics["transfer"] = query_rows(database, f"""
            SELECT connection_id,observed_ns,bytes_sent,bytes_received,source,fidelity
              FROM connection_transfer_evidence
             WHERE connection_id IN ({placeholders}) ORDER BY connection_id
        """, parameters)
    if table_exists(database, "connection_name_resolution_evidence"):
        diagnostics["resolver"] = query_rows(database, f"""
            SELECT e.connection_id,e.query_name,e.result_code,
                   group_concat(a.address,',') AS addresses,e.source,
                   e.observation_fidelity,e.correlation_fidelity,e.relation
              FROM connection_name_resolution_evidence e
              LEFT JOIN connection_name_resolution_addresses a ON a.evidence_id=e.id
             WHERE e.connection_id IN ({placeholders})
             GROUP BY e.id ORDER BY e.connection_id,e.completed_ns
        """, parameters)
    if table_exists(database, "connection_tls_session_evidence"):
        diagnostics["tls"] = query_rows(database, f"""
            SELECT connection_id,local_role,relation,source,observation_fidelity,
                   correlation_fidelity,tls_version,sni,expected_peer_name,
                   matched_peer_name,peer_authenticated,verify_result,spki_sha256,issuer
              FROM connection_tls_session_evidence
             WHERE connection_id IN ({placeholders}) ORDER BY connection_id,observed_ns
        """, parameters)
    if table_exists(database, "verdicts"):
        diagnostics["verdicts"] = query_rows(database, f"""
            SELECT connection_id,performance_state,trust_state,performance_hypothesis,
                   trust_hypothesis,rule_confidence,rule_set_version,rule_set_hash,
                   baseline_hash,input_hash
              FROM verdicts WHERE connection_id IN ({placeholders}) ORDER BY connection_id
        """, parameters)
    return diagnostics


def load_local_findings(database_path: pathlib.Path) -> list[dict[str, Any]]:
    path = pathlib.Path(str(database_path) + ".findings.jsonl")
    if not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
        return []
    findings: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            findings.append(item)
    return findings


def effective_rules(state_dir: pathlib.Path | None) -> dict[str, Any]:
    if state_dir is None:
        return {}
    path = state_dir / "rules" / "active.json"
    if not path.is_file() or path.stat().st_size > 1024 * 1024:
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    rules = []
    for rule in document.get("rules", []):
        if not isinstance(rule, dict):
            continue
        rules.append({key: rule.get(key) for key in
                      ("id", "engine_rule_id", "name", "enabled", "severity", "parameters")})
    return {"id": document.get("id"), "version": document.get("version"),
            "revision": document.get("revision"), "rules": rules}


def count_for_connections(database: sqlite3.Connection, table: str,
                          connection_ids: list[int], predicate: str = "1=1") -> int:
    if not connection_ids or not table_exists(database, table):
        return 0
    placeholders = ",".join("?" for _ in connection_ids)
    query = f"SELECT count(*) FROM {table} WHERE connection_id IN ({placeholders}) AND {predicate}"
    return int(database.execute(query, connection_ids).fetchone()[0])


def collect_one(database: sqlite3.Connection, contract: dict[str, Any],
                local_findings: list[dict[str, Any]], rules: dict[str, Any]) -> dict[str, Any]:
    specification = contract.get("evidence", {})
    failures: list[str] = []
    if specification.get("process_only"):
        failures.append("process-only semantic evidence snapshot is unavailable")
        return {"status": "UNSUPPORTED", "failures": failures, "assurance": {},
                "diagnostics": {"effective_rules": rules}}
    port = specification.get("target_port") or contract.get("detector", {}).get("target_port")
    if not isinstance(port, int):
        return {"status": "UNSUPPORTED", "failures": ["target port is not specified"],
                "assurance": {}, "diagnostics": {"effective_rules": rules}}

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

    diagnostics = connection_diagnostics(database, rows)
    diagnostics["local_findings"] = [
        finding for finding in local_findings
        if finding.get("connection_id") in connection_ids
    ]
    diagnostics["effective_rules"] = rules
    return {"status": "PASS" if not failures else "UNSUPPORTED",
            "connection_ids": connection_ids, "failures": failures,
            "assurance": assurance, "diagnostics": diagnostics}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=pathlib.Path, required=True)
    parser.add_argument("--contracts", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--state-dir", type=pathlib.Path)
    args = parser.parse_args()
    contracts = json.loads(args.contracts.read_text(encoding="utf-8"))["contracts"]
    uri = f"file:{args.database.resolve()}?mode=ro"
    findings = load_local_findings(args.database)
    rules = effective_rules(args.state_dir)
    with sqlite3.connect(uri, uri=True) as database:
        database.row_factory = sqlite3.Row
        scenarios = {scenario: collect_one(database, contract, findings, rules)
                     for scenario, contract in contracts.items()}
    args.output.write_text(json.dumps(
        {"schema_version": 2, "scenarios": scenarios}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
