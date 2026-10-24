"""Unsmoothed n-gram novelty baseline over ordered tool/syscall-class tokens."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def sequence_ngrams(sequence: list[str], n: int) -> list[tuple[str, ...]]:
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive integer")
    if not sequence:
        return []
    padded = ["<s>"] * (n - 1) + list(sequence) + ["</s>"] * (n - 1)
    return [tuple(padded[index:index + n])
            for index in range(len(padded) - n + 1)]


def fit(samples: list[dict[str, Any]], *, n: int = 3
        ) -> dict[str, set[tuple[str, ...]]]:
    model: dict[str, set[tuple[str, ...]]] = defaultdict(set)
    for sample in samples:
        task_type = sample["task_type"]
        model[task_type].update(sequence_ngrams(sample["features"].get("sequences", []), n))
    return dict(model)


def score(sample: dict[str, Any], model: dict[str, set[tuple[str, ...]]], *, n: int = 3
          ) -> tuple[float, list[list[str]]]:
    grams = sequence_ngrams(sample["features"].get("sequences", []), n)
    if not grams:
        return 0.0, []
    known = model.get(sample["task_type"], set())
    unknown = [list(gram) for gram in grams if gram not in known]
    return len(unknown) / len(grams), unknown
