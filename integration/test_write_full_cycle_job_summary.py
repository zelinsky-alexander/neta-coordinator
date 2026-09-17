from __future__ import annotations

import csv
import importlib.util
import pathlib
import sys
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("write_full_cycle_job_summary.py")
SPEC = importlib.util.spec_from_file_location("write_full_cycle_job_summary", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FullCycleJobSummaryTest(unittest.TestCase):
    def test_writes_phase_and_scenario_matrices(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            matrix = root / "matrix.tsv"
            with matrix.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=[
                    "scenario", "result", "ground_truth", "required_evidence",
                    "detector", "portal", "assurance"], delimiter="\t")
                writer.writeheader()
                writer.writerow({"scenario": "003", "result": "PASS",
                                 "ground_truth": "PASS", "required_evidence": "PASS",
                                 "detector": "PASS", "portal": "PASS",
                                 "assurance": "NOT_REQUIRED"})
            output = root / "summary.md"
            MODULE.write_summary(output, "FAIL", {"Lab": 1, "Security": 0}, matrix)
            text = output.read_text(encoding="utf-8")
            self.assertIn("Overall: **FAIL**", text)
            self.assertIn("| Lab | FAIL |", text)
            self.assertIn("| Security | PASS |", text)
            self.assertIn("| 003 | PASS | PASS | PASS | PASS | PASS | NOT_REQUIRED |", text)


if __name__ == "__main__":
    unittest.main()
