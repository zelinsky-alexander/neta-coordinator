#!/usr/bin/env python3
"""Write a concise GitHub Actions summary for a completed full-cycle run."""

from __future__ import annotations

import argparse
import csv
import pathlib


def phase(value: int) -> str:
    return "PASS" if value == 0 else "FAIL"


def write_summary(output: pathlib.Path, status: str, phase_results: dict[str, int],
                  matrix_path: pathlib.Path) -> None:
    lines = ["# NETA Full-Cycle Linux Acceptance", "", f"Overall: **{status}**", "",
             "## Phase matrix", "", "| Phase | Result |", "|---|---|"]
    lines.extend(f"| {name} | {phase(code)} |" for name, code in phase_results.items())
    if matrix_path.is_file():
        with matrix_path.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
        lines.extend(["", "## Scenario contract matrix", "",
                      "| Scenario | Result | Ground truth | Evidence | Detector | Portal | Assurance |",
                      "|---|---|---|---|---|---|---|"])
        for row in rows:
            lines.append(
                f"| {row.get('scenario', '')} | {row.get('result', '')} | "
                f"{row.get('ground_truth', '')} | {row.get('required_evidence', '')} | "
                f"{row.get('detector', '')} | {row.get('portal', '')} | "
                f"{row.get('assurance', '')} |"
            )
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--status", choices=("PASS", "FAIL"), required=True)
    parser.add_argument("--lab-rc", type=int, required=True)
    parser.add_argument("--peer-rc", type=int, required=True)
    parser.add_argument("--security-rc", type=int, required=True)
    parser.add_argument("--acceptance-rc", type=int, required=True)
    parser.add_argument("--matrix", type=pathlib.Path, required=True)
    args = parser.parse_args()
    write_summary(args.output, args.status, {
        "Linux NETA Lab command suite": args.lab_rc,
        "Peer-coordinated inbound scenarios": args.peer_rc,
        "Lab evidence-to-Portal contract": args.acceptance_rc,
        "Unauthenticated ingestion rejection": args.security_rc,
    }, args.matrix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
