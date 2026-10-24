"""Execute a deterministic JSON tool plan through the logged agent tools."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agent.call_log import ToolCallLogger
from agent.tools import AgentTools


def execute_task(task: dict[str, Any], tools: AgentTools) -> list[dict[str, Any]]:
    task_id = task.get("id")
    actions = task.get("actions")
    if not isinstance(task_id, str) or not task_id:
        raise ValueError("task id must be a non-empty string")
    if not isinstance(actions, list):
        raise ValueError("task actions must be a list")
    results = []
    methods = {
        "file_read": tools.read_file,
        "file_write": tools.write_file,
        "shell": tools.shell,
        "http_get": tools.http_get,
    }
    for index, action in enumerate(actions, 1):
        if not isinstance(action, dict) or not isinstance(action.get("args"), dict):
            raise ValueError(f"task {task_id} action {index} needs an args object")
        tool_name = action.get("tool")
        method = methods.get(tool_name)
        if method is None:
            raise ValueError(f"task {task_id} action {index} has unsupported tool {tool_name!r}")
        results.append({"tool": tool_name, "result": method(**action["args"])})
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", required=True, type=Path, help="JSON task action plan")
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--call-log", required=True, type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--cgroup-id", type=int,
                        help="override detected cgroup inode (for isolated tests only)")
    args = parser.parse_args(argv)
    try:
        task = json.loads(args.task.read_text(encoding="utf-8"))
        if not isinstance(task, dict):
            raise ValueError("task must be a JSON object")
        args.workspace.mkdir(parents=True, exist_ok=True)
        logger = ToolCallLogger(args.call_log, run_id=args.run_id or task.get("id"),
                                cgroup_id=args.cgroup_id)
        results = execute_task(task, AgentTools(args.workspace, logger))
    except (OSError, json.JSONDecodeError, TypeError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    if args.results:
        args.results.parent.mkdir(parents=True, exist_ok=True)
        args.results.write_text(json.dumps({"task_id": task["id"], "results": results},
                                           ensure_ascii=False, indent=2) + "\n",
                                encoding="utf-8")
    print(json.dumps({"task_id": task["id"], "tool_calls": len(results)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
