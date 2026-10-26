"""Deterministic summaries for per-strategy mimicry campaign results."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def summarize_campaign(
    runs: list[dict[str, Any]], verdicts: list[dict[str, Any]]
) -> dict[str, Any]:
    """Keep each strategy separate instead of collapsing runs by knowledge flag."""
    by_id: dict[str, dict[str, Any]] = {}
    for run in runs:
        run_id = run.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("every mimicry run needs a run_id")
        if run_id in by_id:
            raise ValueError(f"duplicate mimicry run_id: {run_id}")
        by_id[run_id] = run

    grouped: dict[str, dict[tuple[str, str], list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for verdict in verdicts:
        run_id = verdict.get("run_id")
        if run_id not in by_id:
            raise ValueError(f"verdict references unknown run: {run_id}")
        detector = verdict.get("detector")
        fpr = verdict.get("target_false_positive_rate")
        if not isinstance(detector, str) or not detector or fpr is None:
            raise ValueError("every verdict needs a detector and target FPR")
        grouped[run_id][(detector, str(fpr))].append(verdict)

    by_strategy = {}
    for run_id, run in sorted(by_id.items()):
        detector_results = {}
        for (detector, fpr), entries in sorted(grouped[run_id].items()):
            detected = sum(entry.get("detected") is True for entry in entries)
            detector_results[f"{detector}@FPR={fpr}"] = {
                "detected": detected,
                "runs": len(entries),
                "detection_rate": detected / len(entries),
            }
        by_strategy[run_id] = {
            "strategy": run.get("strategy"),
            "knowledge": run.get("knowledge"),
            "goal_achieved": run.get("goal_achieved"),
            "detectors": detector_results,
        }
    return {
        "runs": len(runs),
        "by_strategy": by_strategy,
        "note": "Deterministic tool-wrapper runs; not a model hijack rate or population estimate.",
    }
