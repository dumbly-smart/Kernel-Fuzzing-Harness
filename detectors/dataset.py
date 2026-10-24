"""Deterministic task-level splits; repeated seeds never cross partitions."""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Any


def split_by_task(samples: list[dict[str, Any]], *, seed: int = 0,
                  calibration_fraction: float = 0.2,
                  test_fraction: float = 0.2) -> dict[str, list[dict[str, Any]]]:
    if calibration_fraction <= 0 or test_fraction <= 0 or \
            calibration_fraction + test_fraction >= 1:
        raise ValueError("calibration/test fractions must be positive and sum to less than one")
    by_type: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list))
    for sample in samples:
        task_type, task_id = sample.get("task_type"), sample.get("task_id")
        if not isinstance(task_type, str) or not task_type or \
                not isinstance(task_id, str) or not task_id:
            raise ValueError("every sample needs string task_type and task_id")
        by_type[task_type][task_id].append(sample)
    assignments: dict[tuple[str, str], str] = {}
    for task_type, by_task in sorted(by_type.items()):
        task_ids = sorted(by_task)
        if len(task_ids) < 3:
            raise ValueError(f"task type {task_type!r} needs at least three distinct tasks")
        random.Random(f"{seed}:{task_type}").shuffle(task_ids)
        train_count = max(1, int(len(task_ids) * (1 - calibration_fraction - test_fraction)))
        calibration_count = max(1, int(len(task_ids) * calibration_fraction))
        if train_count + calibration_count >= len(task_ids):
            train_count = len(task_ids) - 2
            calibration_count = 1
        for task_id in task_ids[:train_count]:
            assignments[(task_type, task_id)] = "train"
        for task_id in task_ids[train_count:train_count + calibration_count]:
            assignments[(task_type, task_id)] = "calibration"
        for task_id in task_ids[train_count + calibration_count:]:
            assignments[(task_type, task_id)] = "test"
    result = {name: [] for name in ("train", "calibration", "test")}
    for sample in samples:
        name = assignments[(sample["task_type"], sample["task_id"])]
        result[name].append(sample)
    return result
