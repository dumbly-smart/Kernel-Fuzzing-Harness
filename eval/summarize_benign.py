#!/usr/bin/env python3
"""Join a completed benign-corpus trace to tool calls and summarize behavior."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tripwire.corpus_report import summarize_behavior
from tripwire.events import iter_events
from tripwire.join import join_events


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def summarize(events_path: Path, calls_path: Path, runs_path: Path,
              output_dir: Path, late_event_grace_ms: float = 250.0) -> dict[str, Any]:
    events = list(iter_events(events_path.read_text(encoding="utf-8").splitlines()))
    calls = read_jsonl(calls_path)
    runs = read_jsonl(runs_path)
    joined = join_events(events, calls, late_event_grace_ms=late_event_grace_ms)
    output_dir.mkdir(parents=True, exist_ok=True)
    joined_path = output_dir / "joined.jsonl"
    with joined_path.open("w", encoding="utf-8") as stream:
        for call in joined["calls"]:
            stream.write(json.dumps(call, sort_keys=True, ensure_ascii=False) + "\n")
    orphan_path = output_dir / "orphan-events.jsonl"
    with orphan_path.open("w", encoding="utf-8") as stream:
        for event in joined["orphan_events"]:
            stream.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")
    behavior = summarize_behavior(runs, joined["calls"])
    report = {
        "join_metrics": joined["metrics"],
        "stats_record_count": sum(event.get("type") == "stats" for event in events),
        "dropped_events": sum(event.get("dropped_events", 0)
                               for event in events if event.get("type") == "stats"),
        "run_count": len(runs),
        "tool_call_count": len(calls),
        "success_count": sum(record.get("success") is True for record in runs),
        "behavior": behavior,
    }
    (output_dir / "corpus-summary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--calls", type=Path, required=True)
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--late-event-grace-ms", type=float, default=250.0)
    args = parser.parse_args(argv)
    report = summarize(args.events, args.calls, args.runs, args.output_dir,
                       args.late_event_grace_ms)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
