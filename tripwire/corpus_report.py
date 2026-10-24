"""Summarize per-run OS behavior without discarding model failures."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


def summarize_behavior(run_records: list[dict[str, Any]],
                       joined_calls: list[dict[str, Any]]) -> dict[str, Any]:
    run_type = {record["run_id"]: record["task_type"] for record in run_records}
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in run_records:
        by_type[record["task_type"]].append(record)
    events_by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for call in joined_calls:
        run_id = call["call_id"].rsplit(":", 1)[0]
        if run_id in run_type:
            events_by_run[run_id].extend(call.get("events", []))

    summaries = {}
    for task_type, records in sorted(by_type.items()):
        feature_runs: dict[str, Counter[str]] = {
            feature: Counter() for feature in ("paths", "binaries", "hosts", "syscalls")
        }
        sequence_lengths = []
        successes = 0
        for record in records:
            run_id = record["run_id"]
            if record.get("success") is True:
                successes += 1
            events = events_by_run.get(run_id, [])
            sequence_lengths.append(len(events))
            found: dict[str, set[str]] = {name: set() for name in feature_runs}
            for event in events:
                syscall = event.get("syscall")
                if isinstance(syscall, str):
                    found["syscalls"].add(syscall)
                    path = event.get("path")
                    if syscall in {"execve", "execveat"} and isinstance(path, str):
                        found["binaries"].add(path)
                    if syscall in {"openat", "renameat", "renameat2", "unlinkat"}:
                        for key in ("path", "path2"):
                            value = event.get(key)
                            if isinstance(value, str) and value:
                                found["paths"].add(value)
                address = event.get("address")
                if isinstance(address, str) and address:
                    found["hosts"].add(address)
                # `comm` is a useful fallback for clone/fork and exec metadata events.
                if event.get("type") in {"process_fork", "process_exit"}:
                    comm = event.get("comm")
                    if isinstance(comm, str) and comm:
                        found["binaries"].add(comm)
            for feature, values in found.items():
                feature_runs[feature].update(values)
        attempts = len(records)
        stable = {name: sorted(value for value, count in counts.items() if count == attempts)
                  for name, counts in feature_runs.items()}
        noisy = {name: sorted(value for value, count in counts.items() if 0 < count < attempts)
                 for name, counts in feature_runs.items()}
        summaries[task_type] = {
            "attempts": attempts,
            "successes": successes,
            "success_rate": successes / attempts if attempts else 0.0,
            "sequence_lengths": sequence_lengths,
            "mean_sequence_length": (sum(sequence_lengths) / attempts) if attempts else 0.0,
            "paths": dict(sorted(feature_runs["paths"].items())),
            "binaries": dict(sorted(feature_runs["binaries"].items())),
            "hosts": dict(sorted(feature_runs["hosts"].items())),
            "syscalls": dict(sorted(feature_runs["syscalls"].items())),
            "stable_features": stable,
            "noisy_features": noisy,
        }
    return {"task_types": summaries, "run_count": len(run_records)}
