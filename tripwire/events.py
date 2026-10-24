"""Strict JSONL reader for the Tripwire event ABI."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any


COMMON_INTEGER_FIELDS = (
    "sequence",
    "monotonic_ns",
    "wall_ns",
    "pid",
    "tgid",
    "ppid",
    "uid",
    "cgroup_id",
)
EVENT_TYPES = {"syscall", "process_fork", "process_exit", "stats"}


def _integer(event: dict[str, Any], key: str, *, minimum: int = 0) -> int:
    value = event.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"field {key!r} must be an integer >= {minimum}")
    return value


def parse_event(line: str) -> dict[str, Any]:
    """Parse and validate one event; errors name the malformed field."""
    try:
        event = json.loads(line)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(event, dict):
        raise ValueError("event must be a JSON object")
    event_type = event.get("type")
    if event_type not in EVENT_TYPES:
        raise ValueError(f"field 'type' must be one of {sorted(EVENT_TYPES)}")
    for key in COMMON_INTEGER_FIELDS:
        _integer(event, key, minimum=1 if key in ("monotonic_ns", "wall_ns", "pid", "tgid") else 0)
    if not isinstance(event.get("comm"), str):
        raise ValueError("field 'comm' must be a string")

    if event_type == "syscall":
        if not isinstance(event.get("syscall"), str) or not event["syscall"]:
            raise ValueError("field 'syscall' must be a non-empty string")
        _integer(event, "return_code", minimum=-(1 << 63))
        for key in ("path", "path2", "address"):
            if key in event and event[key] is not None and not isinstance(event[key], str):
                raise ValueError(f"field {key!r} must be a string or null")
        if "dirfd" in event and event["dirfd"] is not None:
            # openat-style syscalls use -100 (AT_FDCWD) when paths are relative
            # to the process working directory instead of an explicit fd.
            _integer(event, "dirfd", minimum=-100)
        if "fd" in event and event["fd"] is not None:
            # Invalid syscall arguments such as fd=-1 are still useful evidence.
            _integer(event, "fd", minimum=-(1 << 31))
        for key in ("byte_count", "family", "port"):
            if key in event and event[key] is not None:
                _integer(event, key)
    elif event_type == "process_fork":
        _integer(event, "child_pid", minimum=1)
        _integer(event, "child_tgid", minimum=1)
    elif event_type == "stats":
        _integer(event, "dropped_events")
        for key in ("ring_buffer_bytes", "path_bytes", "poll_interval_ms"):
            if key in event:
                _integer(event, key, minimum=1)
    return event


def iter_events(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Yield JSONL events in userspace delivery order and reject sequence gaps."""
    previous_sequence = 0
    for line_number, line in enumerate(lines, start=1):
        try:
            event = parse_event(line)
        except ValueError as exc:
            raise ValueError(f"line {line_number}: {exc}") from exc
        sequence = event["sequence"]
        if sequence != previous_sequence + 1:
            raise ValueError(
                f"line {line_number}: sequence expected {previous_sequence + 1}, got {sequence}"
            )
        previous_sequence = sequence
        yield event
