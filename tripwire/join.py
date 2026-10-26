"""Join cgroup syscall records to logged tool calls using PID ancestry/time."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
from typing import Any, Iterable

from tripwire.events import iter_events


def _integer(record: dict[str, Any], key: str) -> int:
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"field {key!r} must be a non-negative integer")
    return value


def _validate_calls(calls: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    validated = []
    ids = set()
    for line_number, original in enumerate(calls, 1):
        if not isinstance(original, dict):
            raise ValueError(f"call line {line_number}: record must be an object")
        call_record = dict(original)
        call_id = call_record.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            raise ValueError(f"call line {line_number}: call_id must be a non-empty string")
        if call_id in ids:
            raise ValueError(f"call line {line_number}: duplicate call_id {call_id!r}")
        ids.add(call_id)
        for key in ("start_monotonic_ns", "end_monotonic_ns", "tool_pid", "cgroup_id"):
            _integer(call_record, key)
        if call_record["end_monotonic_ns"] < call_record["start_monotonic_ns"]:
            raise ValueError(f"call line {line_number}: end precedes start")
        if not isinstance(call_record.get("tool"), str) or not call_record["tool"]:
            raise ValueError(f"call line {line_number}: tool must be a non-empty string")
        call_record["events"] = []
        validated.append(call_record)
    return validated


def join_events(
    events: Iterable[dict[str, Any]],
    calls: Iterable[dict[str, Any]],
    *,
    late_event_grace_ms: float = 250.0,
) -> dict[str, Any]:
    """Assign each event once, or label it orphaned/ambiguous.

    A process_fork event's PID is the parent; child_pid becomes an ancestry edge.
    Edges are valid only from their fork timestamp onward, reducing PID-reuse
    confusion in short traces.
    """
    if isinstance(late_event_grace_ms, bool) or not isinstance(late_event_grace_ms, (int, float)):
        raise ValueError("late_event_grace_ms must be a non-negative finite number")
    if not math.isfinite(late_event_grace_ms) or late_event_grace_ms < 0:
        raise ValueError("late_event_grace_ms must be a non-negative finite number")
    grace_ns = int(late_event_grace_ms * 1_000_000)
    call_records = _validate_calls(calls)
    event_records = list(events)
    parents_by_child: dict[int, list[tuple[int, int, int]]] = defaultdict(list)
    for event in event_records:
        if event.get("type") == "process_fork":
            child_pid = event.get("child_pid")
            if isinstance(child_pid, int) and not isinstance(child_pid, bool) and child_pid > 0:
                parents_by_child[child_pid].append(
                    (event["pid"], event["monotonic_ns"], event["cgroup_id"])
                )

    def ancestry_distance(pid: int, root_pid: int, at_ns: int, cgroup_id: int) -> int | None:
        pending = [(pid, 0)]
        visited = set()
        while pending:
            current, distance = pending.pop(0)
            if current == root_pid:
                return distance
            if current in visited:
                continue
            visited.add(current)
            for parent, fork_ns, fork_cgroup in parents_by_child.get(current, ()):
                if fork_ns <= at_ns and fork_cgroup == cgroup_id:
                    pending.append((parent, distance + 1))
        return None

    orphan_events = []
    ambiguous_events = []
    stats_records = 0
    for event in event_records:
        event_time = event.get("monotonic_ns")
        event_pid = event.get("pid")
        event_cgroup = event.get("cgroup_id")
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0
               for v in (event_time, event_pid, event_cgroup)):
            raise ValueError("event monotonic_ns, pid, and cgroup_id must be non-negative integers")
        if event.get("type") == "stats":
            stats_records += 1
            continue
        matches = []
        for call_record in call_records:
            if (call_record["cgroup_id"] != event_cgroup
                    or call_record["start_monotonic_ns"] > event_time
                    or event_time > call_record["end_monotonic_ns"] + grace_ns):
                continue
            distance = ancestry_distance(event_pid, call_record["tool_pid"],
                                         event_time, event_cgroup)
            if distance is not None:
                matches.append((distance, call_record))
        if len(matches) == 1:
            matches[0][1]["events"].append(event)
        elif len(matches) > 1:
            closest_distance = min(distance for distance, _ in matches)
            closest = [record for distance, record in matches
                       if distance == closest_distance]
            if len(closest) == 1:
                closest[0]["events"].append(event)
            else:
                ambiguous_events.append(event)
        else:
            orphan_events.append(event)

    event_count = len(event_records) - stats_records
    orphan_count = len(orphan_events)
    ambiguous_count = len(ambiguous_events)
    assigned_count = event_count - orphan_count - ambiguous_count
    metrics = {
        "event_count": event_count,
        "stats_records": stats_records,
        "assigned_events": assigned_count,
        "orphan_events": orphan_count,
        "ambiguous_events": ambiguous_count,
        "orphan_event_rate": orphan_count / event_count if event_count else 0.0,
        "ambiguous_event_rate": ambiguous_count / event_count if event_count else 0.0,
        "late_event_grace_ms": late_event_grace_ms,
    }
    return {
        "calls": call_records,
        "orphan_events": orphan_events,
        "ambiguous_events": ambiguous_events,
        "metrics": metrics,
    }


def _read_calls(path: Path) -> list[dict[str, Any]]:
    calls = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"call line {line_number}: invalid JSON: {exc}") from exc
            calls.append(record)
    return calls


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    config_path = Path(__file__).resolve().parents[1] / "config/tripwire.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--calls", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--late-event-grace-ms", type=float,
                        default=config["late_event_grace_ms"])
    args = parser.parse_args(argv)
    try:
        with args.events.open(encoding="utf-8") as stream:
            events = list(iter_events(stream))
        result = join_events(events, _read_calls(args.calls),
                             late_event_grace_ms=args.late_event_grace_ms)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as stream:
        for call_record in result["calls"]:
            stream.write(json.dumps(call_record, sort_keys=True) + "\n")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({
        "metrics": result["metrics"],
        "orphan_events": result["orphan_events"],
        "ambiguous_events": result["ambiguous_events"],
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["metrics"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
