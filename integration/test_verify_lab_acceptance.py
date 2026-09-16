#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("verify_lab_acceptance.py")
SPEC = importlib.util.spec_from_file_location("verify_lab_acceptance", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AcceptanceComparisonTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = {
            "detector": {
                "required": True,
                "rule_id": "NET-005",
                "semantic_type": "HIGH_OUTBOUND_ASYMMETRY",
                "target_port": 18447,
                "minimum_severity": "low",
                "allowed_statuses": "ACTIVE,CANDIDATE",
                "evidence_root": "required",
                "ruleset_provenance": "required",
            },
            "portal": {"visible_in_all": True, "visible_in_active": "status_dependent"},
        }
        self.finding = {
            "type": "NET-005",
            "semanticType": "HIGH_OUTBOUND_ASYMMETRY",
            "port": 18447,
            "severity": "LOW",
            "status": "CANDIDATE",
            "evidenceRoot": "sha256:" + "1" * 64,
            "ruleSet": {"id": "neta-production", "version": "central-8"},
        }

    def test_complete_chain_passes(self) -> None:
        result = MODULE.result_row(
            "007", self.contract, "PASS", [self.finding], [self.finding],
            {"007": {"status": "PASS"}}, [])
        self.assertEqual("PASS", result["result"])
        self.assertEqual("PASS", result["checks"]["portal"])

    def test_missing_evidence_fails_closed(self) -> None:
        result = MODULE.result_row(
            "007", self.contract, "PASS", [self.finding], [self.finding], {}, [])
        self.assertEqual("FAIL", result["result"])
        self.assertEqual("FAIL:MISSING_OR_INCOMPLETE", result["checks"]["required_evidence"])

    def test_outputs_machine_readable_artifacts(self) -> None:
        result = MODULE.result_row(
            "007", self.contract, "PASS", [self.finding], [self.finding],
            {"007": {"status": "PASS"}}, [])
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary)
            MODULE.write_outputs(output, [result])
            self.assertTrue((output / "expected-vs-actual.json").is_file())
            self.assertTrue((output / "expected-vs-actual.tsv").is_file())
            self.assertTrue((output / "lab-acceptance.junit.xml").is_file())


if __name__ == "__main__":
    unittest.main()
