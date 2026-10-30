#!/usr/bin/env python3
"""Evaluate OS feature ablations with the same task-held-out calibration split."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from detectors.ablations import ABLATIONS, project_features
from detectors.allowlist import score as score_allowlist, train as train_allowlist
from detectors.dataset import split_by_task
from detectors.features import group_run_samples
from detectors.metrics import binary_metrics, threshold_at_fpr
from detectors.ngram import fit as fit_ngrams, score as score_ngrams
from eval.run_detectors import read_jsonl


ROOT = Path(__file__).resolve().parents[1]


def evaluate_ablations(samples: list[dict[str, Any]], detector_config: dict[str, Any],
                       ablation_config: dict[str, Any]
                       ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    attacks = [sample for sample in samples if sample.get("is_attack") is True]
    benign = [sample for sample in samples if sample.get("is_attack") is not True]
    split = split_by_task(
        benign, seed=detector_config["task_split_seed"],
        calibration_fraction=detector_config["calibration_fraction"],
        test_fraction=detector_config["test_fraction"],
    )
    if not split["train"] or not split["calibration"] or not split["test"]:
        raise ValueError("task-level split produced an empty partition")
    names = ablation_config["feature_sets"]
    if not names or any(name not in ABLATIONS for name in names) or len(names) != len(set(names)):
        raise ValueError("ablation feature_sets must be unique supported names")
    if ablation_config.get("combined_score") != \
            "arithmetic_mean_of_allowlist_and_sequence_novelty":
        raise ValueError("unsupported combined_score; update the evaluator before changing this setting")
    order = detector_config["sequence_ngram_order"]
    results: dict[str, Any] = {
        "config": {"detectors": detector_config, "ablations": ablation_config},
        "split_task_counts": {key: len({row["task_id"] for row in rows})
                              for key, rows in split.items()},
        "split_task_ids": {key: sorted({row["task_id"] for row in rows})
                           for key, rows in split.items()},
        "ablations": {},
    }
    false_positives: list[dict[str, Any]] = []
    attack_verdicts: list[dict[str, Any]] = []
    for name in names:
        projected = {id(sample): {**sample, "features": project_features(sample, name)}
                     for group in split.values() for sample in group}
        projected.update({id(sample): {**sample, "features": project_features(sample, name)}
                          for sample in attacks})
        train = [projected[id(sample)] for sample in split["train"]]
        allowlist_model = train_allowlist(train) if name != "sequence" else None
        sequence_model = fit_ngrams(train, n=order) if name in {"sequence", "combined"} else None

        def score(sample: dict[str, Any]) -> tuple[float, dict[str, Any]]:
            item = projected[id(sample)]
            if name == "sequence":
                value, reasons = score_ngrams(item, sequence_model, n=order)
                return value, {"unknown_ngrams": reasons}
            allow_value, allow_reasons = score_allowlist(item, allowlist_model)
            if name == "combined":
                sequence_value, sequence_reasons = score_ngrams(item, sequence_model, n=order)
                return ((allow_value + sequence_value) / 2,
                        {"allowlist": allow_reasons, "unknown_ngrams": sequence_reasons})
            return allow_value, allow_reasons

        partition_scores: dict[str, list[dict[str, Any]]] = {}
        for partition in ("calibration", "test"):
            partition_scores[partition] = []
            records = split[partition] if partition == "calibration" else split["test"] + attacks
            for sample in records:
                value, cause = score(sample)
                partition_scores[partition].append({
                    "run_id": sample["run_id"], "task_id": sample["task_id"],
                    "task_type": sample["task_type"],
                    "is_attack": sample.get("is_attack") is True,
                    "knowledge": sample.get("knowledge"),
                    "goal_achieved": sample.get("goal_achieved"),
                    "score": value, "cause": cause,
                })
        benign_calibration = [row["score"] for row in partition_scores["calibration"]]
        test = partition_scores["test"]
        row_summary = {"calibration_samples": len(benign_calibration),
                       "test_benign_samples": sum(not row["is_attack"] for row in test),
                       "test_attack_samples": sum(row["is_attack"] for row in test),
                       "targets": {}}
        for target in detector_config["target_false_positive_rates"]:
            threshold = threshold_at_fpr(benign_calibration, target)
            metrics = binary_metrics([row["is_attack"] for row in test],
                                     [row["score"] for row in test], threshold)
            metrics["target_false_positive_rate"] = target
            row_summary["targets"][str(target)] = metrics
            for row in test:
                if row["is_attack"]:
                    attack_verdicts.append({
                        "run_id": row["run_id"], "task_id": row["task_id"],
                        "knowledge": row["knowledge"], "goal_achieved": row["goal_achieved"],
                        "ablation": name, "target_false_positive_rate": target,
                        "score": row["score"], "threshold": threshold,
                        "detected": row["score"] > threshold,
                    })
                elif row["score"] > threshold:
                    false_positives.append({
                        "run_id": row["run_id"], "task_id": row["task_id"],
                        "task_type": row["task_type"], "ablation": name,
                        "target_false_positive_rate": target,
                        "score": row["score"], "threshold": threshold,
                        "cause": row["cause"],
                    })
        results["ablations"][name] = row_summary
    results["note"] = (
        "Attack rows are test-only. No attack TPR is defined when the attack set is empty. "
        "The combined score is the configured arithmetic mean; no weights were fit on attacks."
    )
    return results, false_positives, attack_verdicts


def run(corpus_dir: Path, output_dir: Path, detector_config_path: Path,
        ablation_config_path: Path, attack_dir: Path | None = None) -> dict[str, Any]:
    detector_config = json.loads(detector_config_path.read_text(encoding="utf-8"))
    ablation_config = json.loads(ablation_config_path.read_text(encoding="utf-8"))
    runs = read_jsonl(corpus_dir / "runs.jsonl")
    calls = read_jsonl(corpus_dir / "joined.jsonl")
    all_runs = list(runs)
    all_calls = list(calls)
    if attack_dir is not None:
        attack_runs = read_jsonl(attack_dir / "runs.jsonl")
        attack_calls = read_jsonl(attack_dir / "joined.jsonl")
        if any(run.get("is_attack") is not True for run in attack_runs):
            raise ValueError("every attack-dir run must be explicitly labeled is_attack=true")
        all_runs.extend(attack_runs)
        all_calls.extend(attack_calls)
    samples = group_run_samples(all_runs, all_calls)
    summary, false_positives, verdicts = evaluate_ablations(
        samples, detector_config, ablation_config)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "results.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, rows in (("false-positives.jsonl", false_positives),
                       ("attack-verdicts.jsonl", verdicts)):
        with (output_dir / name).open("w", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, default=ROOT / "data/phase3-corpus")
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--attack-dir", type=Path, default=None)
    parser.add_argument("--detector-config", type=Path, default=ROOT / "config/detectors.json")
    parser.add_argument("--ablation-config", type=Path, default=ROOT / "config/ablations.json")
    args = parser.parse_args(argv)
    output_dir = args.output_dir or args.corpus_dir / "ablation-eval"
    try:
        summary = run(args.corpus_dir, output_dir, args.detector_config,
                      args.ablation_config, args.attack_dir)
    except Exception as exc:
        parser.exit(1, f"ERROR: ablation evaluation: {type(exc).__name__}: {exc}\n")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
