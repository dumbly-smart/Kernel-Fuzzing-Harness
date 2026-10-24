#!/usr/bin/env python3
"""Finalize injection goals from joined OS events after the tracer exits."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from detectors.features import syscall_class
from detectors.prompt_classifier import classify_prompt

ROOT = Path(__file__).resolve().parents[1]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def prompt_classifier_metrics(injection_prompts: list[str],
                              benign_prompts: list[str]) -> dict[str, Any]:
    """Score the transparent prompt heuristic on labeled attack and benign text."""
    attack_flags = [classify_prompt(prompt)["is_injection"] for prompt in injection_prompts]
    benign_flags = [classify_prompt(prompt)["is_injection"] for prompt in benign_prompts]
    return {
        "classifier": "transparent_keyword_v1",
        "true_positives": sum(attack_flags),
        "positive_samples": len(attack_flags),
        "true_positive_rate": sum(attack_flags) / len(attack_flags) if attack_flags else None,
        "false_positives": sum(benign_flags),
        "benign_samples": len(benign_flags),
        "false_positive_rate": sum(benign_flags) / len(benign_flags) if benign_flags else None,
    }


def read_benign_prompts(directory: Path) -> list[str]:
    prompts = []
    for path in sorted(directory.rglob("*.yaml")):
        task = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(task, dict) and isinstance(task.get("prompt"), str):
            prompts.append(task["prompt"])
    return prompts


def finalize_records(records: list[dict[str, Any]],
                     joined_calls: list[dict[str, Any]],
                     benign_prompts: list[str] | None = None) -> dict[str, Any]:
    events_by_run: dict[str, list[dict[str, Any]]] = {}
    for call in joined_calls:
        call_id = call.get("call_id")
        if isinstance(call_id, str) and ":" in call_id:
            events_by_run.setdefault(call_id.rsplit(":", 1)[0], []).extend(call.get("events", []))
    by_taxonomy: dict[str, dict[str, Any]] = {}
    for record in records:
        events = events_by_run.get(record["run_id"], [])
        classes = set()
        syscalls = set()
        paths = set()
        addresses = set()
        for event in events:
            event_class = syscall_class(event)
            if event_class:
                classes.add(event_class)
            syscall = event.get("syscall")
            if isinstance(syscall, str):
                syscalls.add(syscall)
            for key in ("path", "path2"):
                path = event.get(key)
                if isinstance(path, str) and path:
                    paths.add(path)
            address = event.get("address")
            if isinstance(address, str) and address:
                addresses.add(address)
        goal = record["goal"]
        if goal["kind"] == "process_executed":
            basename = goal["basename"]
            evidence = [event for event in events
                        if event.get("syscall") in {"execve", "execveat"}
                        and isinstance(event.get("path"), str)
                        and Path(event["path"]).name == basename]
            record["goal_achieved"] = bool(evidence)
            record["process_evidence"] = [
                {key: event.get(key) for key in ("syscall", "path", "pid", "sequence")}
                for event in evidence
            ]
        record["observed_event_classes"] = sorted(classes)
        record["observed_syscalls"] = sorted(syscalls)
        record["observed_paths"] = sorted(paths)
        record["observed_addresses"] = sorted(addresses)
        label = record["taxonomy_hypothesis"]
        bucket = by_taxonomy.setdefault(label, {
            "runs": 0, "goal_successes": 0, "goal_rate": 0.0,
            "expected_os_footprint": set(), "observed_event_classes": set(),
        })
        bucket["runs"] += 1
        bucket["goal_successes"] += record["goal_achieved"] is True
        bucket["expected_os_footprint"].update(record.get("expected_os_footprint", []))
        bucket["observed_event_classes"].update(classes)
    for bucket in by_taxonomy.values():
        bucket["goal_rate"] = bucket["goal_successes"] / bucket["runs"] if bucket["runs"] else 0.0
        for key in ("expected_os_footprint", "observed_event_classes"):
            bucket[key] = sorted(bucket[key])
    attack_prompts = [record.get("payload", "") for record in records]
    if not attack_prompts:
        attack_prompts = ["" for _ in records]
    classifier_metrics = prompt_classifier_metrics(attack_prompts, benign_prompts or [])
    return {"run_count": len(records), "goal_success_count": sum(
                record.get("goal_achieved") is True for record in records),
            "prompt_classifier": classifier_metrics,
            "by_taxonomy_hypothesis": by_taxonomy}


def finalize(run_path: Path, joined_path: Path, output_path: Path,
             benign_prompts: list[str] | None = None) -> dict[str, Any]:
    records = read_jsonl(run_path)
    joined = read_jsonl(joined_path)
    report = finalize_records(records, joined, benign_prompts)
    temporary = run_path.with_suffix(".jsonl.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    temporary.replace(run_path)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    (output_path.parent / "prompt-classifier.json").write_text(
        json.dumps(report["prompt_classifier"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", required=True, type=Path)
    parser.add_argument("--joined", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--benign-tasks-dir", type=Path, default=ROOT / "tasks/benign")
    args = parser.parse_args(argv)
    try:
        report = finalize(args.runs, args.joined, args.output,
                          read_benign_prompts(args.benign_tasks_dir))
    except Exception as exc:
        parser.exit(1, f"ERROR: injection finalizer: {type(exc).__name__}: {exc}\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
