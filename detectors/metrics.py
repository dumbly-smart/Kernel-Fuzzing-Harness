"""Threshold calibration and binary metrics with explicit empty-class values."""

from __future__ import annotations

import math
from typing import Any


def _scores(scores: list[float]) -> list[float]:
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or
           not math.isfinite(value) for value in scores):
        raise ValueError("detector scores must be finite numbers")
    return [float(value) for value in scores]


def threshold_at_fpr(benign_scores: list[float], target_fpr: float) -> float:
    """Choose a calibration cutoff whose strict `score > cutoff` rate is capped."""
    values = _scores(benign_scores)
    if isinstance(target_fpr, bool) or not isinstance(target_fpr, (int, float)) or \
            not math.isfinite(target_fpr) or not 0 <= target_fpr <= 1:
        raise ValueError("target_fpr must be a finite number between zero and one")
    if not values:
        raise ValueError("cannot calibrate a threshold without benign scores")
    allowed = math.floor(float(target_fpr) * len(values))
    if allowed == 0:
        return max(values)
    ordered = sorted(values)
    # Strict comparisons make ties conservative: a tied score never exceeds the cutoff.
    return ordered[len(ordered) - allowed - 1]


def binary_metrics(labels: list[bool], scores: list[float], threshold: float
                   ) -> dict[str, Any]:
    values = _scores(scores)
    if len(labels) != len(values):
        raise ValueError("labels and scores must have equal lengths")
    if any(type(label) is not bool for label in labels):
        raise ValueError("labels must be booleans")
    cutoff = _scores([threshold])[0]
    predicted = [value > cutoff for value in values]
    tp = sum(actual and guess for actual, guess in zip(labels, predicted))
    fp = sum(not actual and guess for actual, guess in zip(labels, predicted))
    positives = sum(labels)
    negatives = len(labels) - positives
    tn = negatives - fp
    fn = positives - tp
    return {
        "samples": len(labels), "threshold": cutoff,
        "true_positives": tp, "false_positives": fp,
        "true_negatives": tn, "false_negatives": fn,
        "true_positive_rate": tp / positives if positives else None,
        "false_positive_rate": fp / negatives if negatives else None,
    }
