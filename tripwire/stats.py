"""Validation helpers for collector-side periodic records."""

from __future__ import annotations

from math import ceil
from typing import Any, Iterable


def validate_stats_cadence(events: Iterable[dict[str, Any]], poll_interval_ms: int) -> int:
    """Reject a stats stream that is substantially faster than its configured interval.

    One record is allowed at startup and shutdown, plus one per elapsed period.
    The tolerance handles signal and scheduler timing around interval boundaries.
    """
    if isinstance(poll_interval_ms, bool) or not isinstance(poll_interval_ms, int) or poll_interval_ms <= 0:
        raise ValueError("poll_interval_ms must be a positive integer")
    records = list(events)
    if any(isinstance(event.get("monotonic_ns"), bool)
           or not isinstance(event.get("monotonic_ns"), int)
           or event["monotonic_ns"] < 0 for event in records):
        raise ValueError("all events need a non-negative monotonic_ns")
    stats_count = sum(event.get("type") == "stats" for event in records)
    if not records:
        return stats_count
    elapsed_ns = max(event["monotonic_ns"] for event in records) - min(
        event["monotonic_ns"] for event in records)
    interval_ns = poll_interval_ms * 1_000_000
    maximum = 2 + ceil(elapsed_ns / interval_ns)
    if stats_count > maximum:
        raise ValueError(
            f"stats records exceed configured cadence: {stats_count} records in "
            f"{elapsed_ns} ns; maximum allowed is {maximum} for {poll_interval_ms} ms"
        )
    return stats_count
