"""Append-only tool-call records using the same monotonic clock as the tracer."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable
import uuid


def current_cgroup_id() -> int:
    """Resolve this process's cgroup v2 directory to the inode used by BPF."""
    entries = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    unified = next((line.split("::", 1)[1] for line in entries if line.startswith("0::")), None)
    if unified is None:
        raise RuntimeError("current process is not in a cgroup v2 hierarchy")
    cgroup_path = (Path("/sys/fs/cgroup") / unified.lstrip("/")).resolve(strict=True)
    root = Path("/sys/fs/cgroup").resolve(strict=True)
    if cgroup_path != root and not cgroup_path.is_relative_to(root):
        raise RuntimeError("process cgroup path escaped /sys/fs/cgroup")
    return cgroup_path.stat().st_ino


@dataclass
class ToolCallContext:
    """Mutable process identity filled after a tool subprocess is started."""

    tool_pid: int
    tool_tgid: int
    tool_ppid: int

    def set_process(self, pid: int, *, tgid: int | None = None, ppid: int | None = None) -> None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("tool PID must be a positive integer")
        self.tool_pid = pid
        self.tool_tgid = pid if tgid is None else tgid
        self.tool_ppid = os.getpid() if ppid is None else ppid


class ToolCallLogger:
    """Write one flushed JSONL record after every tool invocation."""

    def __init__(self, path: Path, *, run_id: str | None = None,
                 cgroup_id: int | None = None):
        self.path = path
        self.run_id = run_id or uuid.uuid4().hex
        if not self.run_id or any(char in self.run_id for char in "\r\n:"):
            raise ValueError("run_id must be non-empty and cannot contain colon or newline")
        self.cgroup_id = current_cgroup_id() if cgroup_id is None else cgroup_id
        if isinstance(self.cgroup_id, bool) or not isinstance(self.cgroup_id, int) or self.cgroup_id < 0:
            raise ValueError("cgroup_id must be a non-negative integer")
        self._counter = 0
        self._lock = threading.Lock()

    def invoke(self, tool: str, args: dict[str, Any], action: Callable[[ToolCallContext], Any]) -> Any:
        if not isinstance(tool, str) or not tool:
            raise ValueError("tool must be a non-empty string")
        if not isinstance(args, dict):
            raise ValueError("tool args must be a JSON object")
        # Fail before running the tool if its arguments cannot be persisted.
        json.dumps(args, ensure_ascii=False, allow_nan=False)
        with self._lock:
            self._counter += 1
            call_id = f"{self.run_id}:{self._counter:04d}"
        caller_pid = os.getpid()
        caller_tgid = caller_pid
        caller_ppid = os.getppid()
        context = ToolCallContext(caller_pid, caller_tgid, caller_ppid)
        start_ns = time.monotonic_ns()
        ok = False
        error_type = None
        try:
            result = action(context)
            ok = True
            return result
        except Exception as exc:
            error_type = type(exc).__name__
            raise
        finally:
            end_ns = max(start_ns, time.monotonic_ns())
            record = {
                "call_id": call_id,
                "tool": tool,
                "args": args,
                "start_monotonic_ns": start_ns,
                "end_monotonic_ns": end_ns,
                "pid": caller_pid,
                "tgid": caller_tgid,
                "ppid": caller_ppid,
                "tool_pid": context.tool_pid,
                "tool_tgid": context.tool_tgid,
                "tool_ppid": context.tool_ppid,
                "cgroup_id": self.cgroup_id,
                "ok": ok,
            }
            if error_type is not None:
                record["error_type"] = error_type
            self.path.parent.mkdir(parents=True, exist_ok=True)
            encoded = json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False)
            with self._lock, self.path.open("a", encoding="utf-8") as stream:
                stream.write(encoded + "\n")
                stream.flush()
