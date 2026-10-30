"""Convert joined tool/syscall records into explicit detector features."""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath
import re
from typing import Any


_SYSCALL_CLASSES = {
    "execve": "process_exec", "execveat": "process_exec",
    "clone": "process_create", "clone3": "process_create",
    "fork": "process_create", "vfork": "process_create",
    "openat": "file_open", "unlinkat": "file_unlink",
    "renameat": "file_rename", "renameat2": "file_rename",
    "connect": "network_connect", "sendto": "network_send",
    # The tracer reports write only when the fd resolves to a socket.
    "write": "network_write",
}
_CORPUS_RUN_DIR = re.compile(r"(?:phase3|mimicry)-corpus-[0-9a-f]{12}\Z")


def syscall_class(event: dict[str, Any]) -> str | None:
    """Map syscall and lifecycle events to a stable, documented token class."""
    event_type = event.get("type")
    if event_type == "syscall":
        name = event.get("syscall")
        return _SYSCALL_CLASSES.get(name, "other_syscall") if isinstance(name, str) else None
    if event_type == "process_fork":
        return "process_fork"
    if event_type == "process_exit":
        return "process_exit"
    return None


def _path_feature(path: str, run_id: str) -> str:
    """Normalize workspace IDs and generated corpus roots, retaining path identity."""
    parsed = PurePosixPath(path)
    parts = parsed.parts
    for index, part in enumerate(parts[:-2]):
        if part == "workspaces" and parts[index + 1] == run_id:
            suffix = PurePosixPath(*parts[index + 2:]).as_posix()
            return f"workspace/{suffix}"
    for index, part in enumerate(parts):
        if _CORPUS_RUN_DIR.fullmatch(part):
            return PurePosixPath(*parts[:index], "corpus-run", *parts[index + 1:]).as_posix()
    return parsed.as_posix()


def extract_sample_features(run_id: str, task_type: str,
                            joined_calls: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract sets for allowlists and an ordered (tool, syscall-class) sequence."""
    features: dict[str, set[str]] = {
        "paths": set(), "binaries": set(), "hosts": set(), "syscalls": set(),
    }
    sequences: list[str] = []
    ordered_calls = sorted(joined_calls, key=lambda call: call.get("start_monotonic_ns", 0))
    for call in ordered_calls:
        tool = call.get("tool", "unknown_tool")
        events = sorted(call.get("events", []), key=lambda event: event.get("sequence", 0))
        for event in events:
            event_type = event.get("type")
            syscall = event.get("syscall")
            token_class = syscall_class(event)
            if token_class is not None:
                sequences.append(f"{tool}|{token_class}")
            if isinstance(syscall, str):
                features["syscalls"].add(syscall)
                if syscall in {"openat", "unlinkat", "renameat", "renameat2"}:
                    for key in ("path", "path2"):
                        path = event.get(key)
                        if isinstance(path, str) and path:
                            features["paths"].add(_path_feature(path, run_id))
                if syscall in {"execve", "execveat"}:
                    path = event.get("path")
                    if isinstance(path, str) and path:
                        features["binaries"].add(path)
            if event_type in {"process_fork", "process_exit"}:
                comm = event.get("comm")
                if isinstance(comm, str) and comm:
                    features["binaries"].add(comm)
            address = event.get("address")
            if isinstance(address, str) and address:
                port = event.get("port")
                features["hosts"].add(f"{address}:{port}" if isinstance(port, int) else address)
    return {
        "run_id": run_id,
        "task_type": task_type,
        **{key: sorted(values) for key, values in features.items()},
        "sequences": sequences,
    }


def group_run_samples(run_records: list[dict[str, Any]],
                      joined_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return one sample per attempted run, including runs with no calls/events."""
    by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    run_ids: set[str] = set()
    validated_runs: list[tuple[dict[str, Any], str, str]] = []
    for run in run_records:
        run_id, task_type = run.get("run_id"), run.get("task_type")
        if not isinstance(run_id, str) or not run_id or not isinstance(task_type, str):
            raise ValueError("every run record needs non-empty string run_id and string task_type")
        if run_id in run_ids:
            raise ValueError(f"duplicate run_id in run records: {run_id}")
        run_ids.add(run_id)
        validated_runs.append((run, run_id, task_type))

    call_ids = set()
    for call in joined_calls:
        call_id = call.get("call_id")
        if not isinstance(call_id, str) or ":" not in call_id:
            raise ValueError(f"malformed call_id in joined calls: {call_id!r}")
        run_id, counter = call_id.rsplit(":", 1)
        if not run_id or not counter.isascii() or not counter.isdigit():
            raise ValueError(f"malformed call_id in joined calls: {call_id!r}")
        if call_id in call_ids:
            raise ValueError(f"duplicate call_id in joined calls: {call_id}")
        call_ids.add(call_id)
        if run_id not in run_ids:
            raise ValueError(f"joined call {call_id} has no matching run")
        by_run[run_id].append(call)

    samples = []
    for run, run_id, task_type in validated_runs:
        calls = by_run.get(run_id, [])
        samples.append({
            "run_id": run_id,
            "task_id": run.get("task_id"),
            "task_type": task_type,
            "success": run.get("success") is True,
            "is_attack": run.get("is_attack") is True,
            "knowledge": run.get("knowledge"),
            "strategy": run.get("strategy"),
            "goal_achieved": run.get("goal_achieved"),
            "features": extract_sample_features(run_id, task_type, calls),
        })
    return samples
