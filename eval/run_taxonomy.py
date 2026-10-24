#!/usr/bin/env python3
"""Build per-injection taxonomy rows from finalized traces and OS verdicts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from eval.run_detectors import read_jsonl
from eval.taxonomy import build_taxonomy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attack-dir", type=Path, default=Path("data/injection-corpus"))
    parser.add_argument("--detector-dir", type=Path, default=None,
                        help="directory containing attack-verdicts.jsonl (defaults under attack-dir)")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    detector_dir = args.detector_dir or args.attack_dir / "detector-eval"
    output = args.output or args.attack_dir / "taxonomy-results.json"
    try:
        records = read_jsonl(args.attack_dir / "runs.jsonl")
        verdicts = read_jsonl(detector_dir / "attack-verdicts.jsonl")
        report = build_taxonomy(records, verdicts)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
    except Exception as exc:
        parser.exit(1, f"ERROR: taxonomy evaluation: {type(exc).__name__}: {exc}\n")
    print(json.dumps({"case_count": report["case_count"],
                      "pending_count": sum(row["measured_class"] == "pending"
                                           for row in report["cases"]),
                      "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
