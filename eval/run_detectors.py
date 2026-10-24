#!/usr/bin/env python3
"""Train benign OS-behavior baselines and score task-held-out runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from detectors.allowlist import score as score_allowlist, train as train_allowlist
from detectors.dataset import split_by_task
from detectors.features import group_run_samples
from detectors.metrics import binary_metrics, threshold_at_fpr
from detectors.ngram import fit as fit_ngrams, score as score_ngrams


ROOT = Path(__file__).resolve().parents[1]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            records.append(value)
    return records


def evaluate(samples: list[dict[str, Any]], config: dict[str, Any]
             ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Fit on train tasks, calibrate on calibration tasks, evaluate held-out tasks."""
    split = split_by_task(
        samples,
        seed=config["task_split_seed"],
        calibration_fraction=config["calibration_fraction"],
        test_fraction=config["test_fraction"],
    )
    if not split["train"] or not split["calibration"] or not split["test"]:
        raise ValueError("task-level split produced an empty partition")
    models = {
        "per_task_type_allowlist": train_allowlist(split["train"]),
        "tool_syscall_ngram": fit_ngrams(
            split["train"], n=config["sequence_ngram_order"]),
    }
    score_functions = {
        "per_task_type_allowlist": lambda sample: score_allowlist(
            sample, models["per_task_type_allowlist"]),
        "tool_syscall_ngram": lambda sample: score_ngrams(
            sample, models["tool_syscall_ngram"], n=config["sequence_ngram_order"]),
    }
    scored: list[dict[str, Any]] = []
    for partition, records in split.items():
        for sample in records:
            for detector, score_function in score_functions.items():
                score_value, causes = score_function(sample)
                scored.append({
                    "run_id": sample["run_id"], "task_id": sample["task_id"],
                    "task_type": sample["task_type"], "partition": partition,
                    "is_attack": sample.get("is_attack", False) is True,
                    "task_success": sample.get("success", False),
                    "detector": detector, "score": score_value, "causes": causes,
                })

    summary = {
        "config": config,
        "split_task_counts": {name: len({s["task_id"] for s in rows})
                              for name, rows in split.items()},
        "split_run_counts": {name: len(rows) for name, rows in split.items()},
        "task_ids": {name: sorted({s["task_id"] for s in rows})
                     for name, rows in split.items()},
        "detectors": {},
    }
    false_positives = []
    for detector in score_functions:
        calibration = [row for row in scored
                       if row["partition"] == "calibration" and row["detector"] == detector
                       and not row["is_attack"]]
        test = [row for row in scored
                if row["partition"] == "test" and row["detector"] == detector]
        if not calibration or not test:
            raise ValueError(f"detector {detector} has no calibration or test records")
        detector_summary = {"calibration_samples": len(calibration), "test_samples": len(test),
                            "targets": {}}
        for target_fpr in config["target_false_positive_rates"]:
            threshold = threshold_at_fpr([row["score"] for row in calibration], target_fpr)
            metrics = binary_metrics([row["is_attack"] for row in test],
                                     [row["score"] for row in test], threshold)
            metrics["target_false_positive_rate"] = target_fpr
            detector_summary["targets"][str(target_fpr)] = metrics
            for row in test:
                if not row["is_attack"] and row["score"] > threshold:
                    false_positives.append({
                        "run_id": row["run_id"], "task_id": row["task_id"],
                        "task_type": row["task_type"], "detector": detector,
                        "target_false_positive_rate": target_fpr,
                        "score": row["score"], "threshold": threshold,
                        "cause": row["causes"],
                    })
        summary["detectors"][detector] = detector_summary
    summary["note"] = (
        "Thresholds use benign calibration tasks; metrics use task-held-out test runs. "
        "TPR is null until labeled injections are included. Small calibration sets may "
        "not resolve 1% or 5% FPR; report their sample counts and measured test FPR."
    )
    return summary, scored, false_positives


def run(corpus_dir: Path, output_dir: Path, config_path: Path) -> dict[str, Any]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    runs = read_jsonl(corpus_dir / "runs.jsonl")
    calls = read_jsonl(corpus_dir / "joined.jsonl")
    manifest_path = corpus_dir / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    else:
        manifest = {}
    samples = group_run_samples(runs, calls)
    summary, scored, false_positives = evaluate(samples, config)
    summary["corpus"] = {
        "model": manifest.get("model"),
        "model_runtime": manifest.get("model_runtime"),
        "model_lock": manifest.get("model_lock"),
        "run_count": len(runs),
        "task_successes": sum(run.get("success") is True for run in runs),
        "task_success_rate": (sum(run.get("success") is True for run in runs) / len(runs)
                              if runs else None),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "results.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8")
    for name, records in (("scores.jsonl", scored), ("false-positives.jsonl", false_positives)):
        with (output_dir / name).open("w", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, default=ROOT / "data/phase3-corpus")
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--config", type=Path, default=ROOT / "config/detectors.json")
    args = parser.parse_args(argv)
    output_dir = args.output_dir or args.corpus_dir / "detector-eval"
    try:
        summary = run(args.corpus_dir, output_dir, args.config)
    except Exception as exc:
        parser.exit(1, f"ERROR: detector evaluation: {type(exc).__name__}: {exc}\n")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
