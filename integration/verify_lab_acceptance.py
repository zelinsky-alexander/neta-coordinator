#!/usr/bin/env python3
"""Compare executable lab contracts with agent, coordinator, and Portal results."""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
import sys
import xml.etree.ElementTree as ET
from typing import Any

SEVERITY = {"low": 1, "medium": 2, "high": 3}
SUCCESS_GROUND_TRUTH = {"PASS"}


def load_json(path: pathlib.Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def items(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return [row for row in document if isinstance(row, dict)]
    if isinstance(document, dict):
        rows = document.get("items", document.get("findings", []))
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    raise ValueError("finding snapshot must contain an items or findings array")


def split(value: Any) -> set[str]:
    if value in {None, "", "NONE"}:
        return set()
    return {part.strip().upper() for part in str(value).split(",") if part.strip()}


def value(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return None


def rule_id(row: dict[str, Any]) -> str:
    return str(value(row, "ruleId", "rule_id", "type") or "").upper()


def matching(rows: list[dict[str, Any]], detector: dict[str, Any]) -> list[dict[str, Any]]:
    expected_rule = str(detector.get("rule_id", "")).upper()
    expected_port = detector.get("target_port")
    expected_subject = str(detector.get("subject_type", "")).upper()
    result = []
    for row in rows:
        if rule_id(row) != expected_rule:
            continue
        if expected_port is not None and int(value(row, "port", "target_port") or 0) != expected_port:
            continue
        if expected_subject and str(value(row, "subjectType", "subject_type") or "").upper() != expected_subject:
            continue
        result.append(row)
    return result


def ground_truth(path: pathlib.Path, peer_path: pathlib.Path | None) -> dict[str, str]:
    document = load_json(path)
    result = {str(row["scenario"]): str(row["status"]).upper()
              for row in document.get("results", [])}
    if peer_path and peer_path.exists():
        with peer_path.open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream, delimiter="\t"):
                result[str(row["scenario"])] = str(row["status"]).upper()
    return result


def result_row(scenario: str, contract: dict[str, Any], ground: str,
               coordinator: list[dict[str, Any]], portal: list[dict[str, Any]],
               evidence: dict[str, Any],
               portal_active: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    detector = contract["detector"]
    checks: dict[str, str] = {
        "ground_truth": "PASS" if ground in SUCCESS_GROUND_TRUTH else f"FAIL:{ground or 'MISSING'}"
    }
    failures = [] if checks["ground_truth"] == "PASS" else [checks["ground_truth"]]

    scenario_evidence = evidence.get(scenario)
    evidence_required = bool(contract.get("evidence", {}).get("required", detector.get("required", False)))
    if evidence_required:
        checks["required_evidence"] = "PASS" if isinstance(scenario_evidence, dict) and scenario_evidence.get("status") == "PASS" else "FAIL:MISSING_OR_INCOMPLETE"
        if checks["required_evidence"] != "PASS": failures.append(checks["required_evidence"])
    else:
        checks["required_evidence"] = "NOT_REQUIRED"

    forbidden = split(detector.get("forbidden_rules"))
    contract_port = contract.get("evidence", {}).get("target_port")
    relevant_rows = coordinator
    if isinstance(contract_port, int):
        relevant_rows = [row for row in coordinator
                         if int(value(row, "port", "target_port") or 0) == contract_port]
    observed_rules = {rule_id(row) for row in relevant_rows}
    forbidden_seen = sorted(forbidden & observed_rules)
    checks["forbidden_results"] = "PASS" if not forbidden_seen else "FAIL:" + ",".join(forbidden_seen)
    if forbidden_seen: failures.append(checks["forbidden_results"])

    if detector.get("required"):
        coordinator_matches = matching(coordinator, detector)
        portal_matches = matching(portal, detector)
        active_portal_matches = matching(portal_active or [], detector)
        checks["detector"] = "PASS" if coordinator_matches else "FAIL:MISSING"
        checks["announcement"] = checks["detector"]
        checks["coordinator_db"] = checks["detector"]
        if not coordinator_matches:
            failures.append("detector:missing")
        else:
            minimum = SEVERITY[str(detector["minimum_severity"]).lower()]
            severity_ok = any(SEVERITY.get(str(value(row, "severity") or "").lower(), 0) >= minimum
                              for row in coordinator_matches)
            statuses = split(detector["allowed_statuses"])
            status_ok = any(str(value(row, "status") or "").upper() in statuses
                            for row in coordinator_matches)
            evidence_root_ok = any(str(value(row, "evidenceRoot", "evidence_root") or "").startswith("sha256:")
                                   for row in coordinator_matches)
            ruleset_ok = any(value(row, "ruleSet", "rule_set") not in (None, "", {})
                             for row in coordinator_matches)
            semantic = str(detector["semantic_type"]).upper()
            semantic_ok = any(str(value(row, "semanticType", "semantic_type") or "").upper() == semantic
                              for row in coordinator_matches)
            checks["coordinator_status"] = "PASS" if status_ok else "FAIL:STATUS"
            checks["coordinator_severity"] = "PASS" if severity_ok else "FAIL:SEVERITY"
            checks["evidence_root"] = "PASS" if evidence_root_ok else "FAIL:EVIDENCE_ROOT"
            checks["ruleset_provenance"] = "PASS" if ruleset_ok else "FAIL:RULESET"
            checks["semantic_type"] = "PASS" if semantic_ok else "FAIL:SEMANTIC_TYPE"
            for key in ("coordinator_status", "coordinator_severity", "evidence_root",
                        "ruleset_provenance", "semantic_type"):
                if checks[key] != "PASS": failures.append(checks[key])
        active_expected = any(str(value(row, "status") or "").upper() == "ACTIVE"
                              for row in coordinator_matches)
        active_visibility_ok = bool(active_portal_matches) == active_expected
        checks["portal"] = "PASS" if portal_matches and active_visibility_ok else "FAIL:FILTER_VISIBILITY"
        if checks["portal"] != "PASS": failures.append("portal:filter-visibility")
    else:
        checks.update({"detector": "NOT_REQUIRED", "announcement": "NOT_REQUIRED",
                       "coordinator_db": "NOT_REQUIRED", "coordinator_status": "NOT_REQUIRED",
                       "portal": "NOT_REQUIRED"})

    assurance = contract.get("assurance", {})
    if assurance:
        observed = scenario_evidence.get("assurance", {}) if isinstance(scenario_evidence, dict) else {}
        assurance_ok = all(str(observed.get(key, "")).upper() == str(expected).upper()
                           for key, expected in assurance.items())
        checks["assurance"] = "PASS" if assurance_ok else "FAIL:MISMATCH_OR_MISSING"
        if not assurance_ok: failures.append(checks["assurance"])
    else:
        checks["assurance"] = "NOT_REQUIRED"

    return {"scenario": scenario, "result": "PASS" if not failures else "FAIL",
            "checks": checks, "failures": failures}


def write_outputs(output: pathlib.Path, results: list[dict[str, Any]]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    overall = "PASS" if all(row["result"] == "PASS" for row in results) else "FAIL"
    document = {"schema_version": 1, "result": overall, "scenarios": results}
    (output / "expected-vs-actual.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    columns = ["scenario", "result", "ground_truth", "required_evidence", "detector",
               "announcement", "coordinator_db", "coordinator_status", "portal",
               "forbidden_results", "assurance"]
    with (output / "expected-vs-actual.tsv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, delimiter="\t")
        writer.writeheader()
        for row in results:
            writer.writerow({"scenario": row["scenario"], "result": row["result"],
                             **{key: row["checks"].get(key, "") for key in columns[2:]}})

    suite = ET.Element("testsuite", name="neta-lab-detection-acceptance",
                       tests=str(len(results)),
                       failures=str(sum(row["result"] != "PASS" for row in results)))
    for row in results:
        case = ET.SubElement(suite, "testcase", classname="neta.lab.acceptance",
                             name=f"NETA-LAB-{row['scenario']}")
        if row["result"] != "PASS":
            failure = ET.SubElement(case, "failure", message="; ".join(row["failures"]))
            failure.text = json.dumps(row["checks"], sort_keys=True)
    ET.ElementTree(suite).write(output / "lab-acceptance.junit.xml",
                                encoding="utf-8", xml_declaration=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contracts", type=pathlib.Path, required=True)
    parser.add_argument("--ground-truth", type=pathlib.Path, required=True)
    parser.add_argument("--peer-ground-truth", type=pathlib.Path)
    parser.add_argument("--coordinator-findings", type=pathlib.Path, required=True)
    parser.add_argument("--portal-findings", type=pathlib.Path, required=True)
    parser.add_argument("--portal-active-findings", type=pathlib.Path, required=True)
    parser.add_argument("--agent-evidence", type=pathlib.Path, required=True)
    parser.add_argument("--scenarios", default="all")
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()

    contracts = load_json(args.contracts).get("contracts", {})
    selected = set(contracts) if args.scenarios == "all" else set(args.scenarios.split(","))
    unknown = selected - set(contracts)
    if unknown:
        raise ValueError("unknown scenarios: " + ",".join(sorted(unknown)))
    ground = ground_truth(args.ground_truth, args.peer_ground_truth)
    coordinator = items(load_json(args.coordinator_findings))
    portal = items(load_json(args.portal_findings))
    portal_active = items(load_json(args.portal_active_findings))
    evidence_doc = load_json(args.agent_evidence)
    evidence = evidence_doc.get("scenarios", {}) if isinstance(evidence_doc, dict) else {}
    results = [result_row(scenario, contracts[scenario], ground.get(scenario, ""),
                          coordinator, portal, evidence, portal_active)
               for scenario in sorted(selected)]
    write_outputs(args.output_dir, results)
    return 0 if all(row["result"] == "PASS" for row in results) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"lab acceptance verification failed: {error}", file=sys.stderr)
        raise SystemExit(2)
