"""Per-task-type allowlist baseline over OS-visible feature sets."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


FEATURE_FIELDS = ("paths", "binaries", "hosts", "syscalls")


def train(samples: list[dict[str, Any]]) -> dict[str, dict[str, list[str]]]:
    profiles: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {field: set() for field in FEATURE_FIELDS})
    for sample in samples:
        task_type = sample["task_type"]
        features = sample["features"]
        for field in FEATURE_FIELDS:
            profiles[task_type][field].update(features.get(field, []))
    return {task_type: {field: sorted(values) for field, values in fields.items()}
            for task_type, fields in profiles.items()}


def score(sample: dict[str, Any], model: dict[str, dict[str, list[str]]]
          ) -> tuple[float, dict[str, list[str]]]:
    task_type = sample["task_type"]
    profile = model.get(task_type, {})
    unknown: dict[str, list[str]] = {}
    feature_count = 0
    unknown_count = 0
    for field in FEATURE_FIELDS:
        values = set(sample["features"].get(field, []))
        allowed = set(profile.get(field, []))
        unseen = sorted(values - allowed)
        feature_count += len(values)
        unknown_count += len(unseen)
        if unseen:
            unknown[field] = unseen
    return (unknown_count / feature_count if feature_count else 0.0), unknown
