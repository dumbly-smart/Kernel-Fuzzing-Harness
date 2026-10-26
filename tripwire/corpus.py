"""Load and validate human-readable benign task definitions."""

from __future__ import annotations

import json
import ipaddress
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml


TASK_TYPES = {"edit", "search", "tests", "fetch", "summarize"}
TASK_TOOLS = {"file_read", "file_write", "shell", "http_get"}
SUCCESS_CHECKS = {
    "file_exists", "file_contains", "final_contains",
    "tool_result_contains", "tool_results_contain",
}


def _workspace_relative(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{where} must be a workspace-relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"{where} must be a workspace-relative path")
    return value


def validate_task(task: Any) -> dict[str, Any]:
    if not isinstance(task, dict):
        raise ValueError("task must be a YAML mapping")
    required = {"id", "task_type", "prompt", "allowed_tools", "fixtures", "success"}
    optional = {"local_http"}
    missing = required - set(task)
    extra = set(task) - required - optional
    if missing or extra:
        raise ValueError(f"task fields mismatch; missing={sorted(missing)}, extra={sorted(extra)}")
    if not isinstance(task["id"], str) or not task["id"].strip():
        raise ValueError("task id must be a non-empty string")
    if not isinstance(task["task_type"], str) or task["task_type"] not in TASK_TYPES:
        raise ValueError(f"task {task['id']} has unsupported task_type")
    if not isinstance(task["prompt"], str) or not task["prompt"].strip():
        raise ValueError(f"task {task['id']} prompt must be a non-empty string")
    tools = task["allowed_tools"]
    if (not isinstance(tools, list) or not tools or
            any(not isinstance(tool, str) or tool not in TASK_TOOLS for tool in tools)):
        raise ValueError(f"task {task['id']} has unsupported tool in allowed_tools")
    local_http = task.get("local_http")
    if local_http is not None:
        if (task["task_type"] != "fetch" or not isinstance(local_http, dict) or
                set(local_http) != {"path", "body"}):
            raise ValueError(f"task {task['id']} local_http fixture is invalid")
        route = local_http["path"]
        if (not isinstance(route, str) or not route.startswith("/") or ".." in route.split("/") or
                not isinstance(local_http["body"], str)):
            raise ValueError(f"task {task['id']} local_http fixture is invalid")
    fixtures = task["fixtures"]
    if not isinstance(fixtures, dict):
        raise ValueError(f"task {task['id']} fixtures must be a mapping")
    for path, content in fixtures.items():
        _workspace_relative(path, f"task {task['id']} fixture path")
        if not isinstance(content, str):
            raise ValueError(f"task {task['id']} fixture content must be a string")
    success = task["success"]
    if not isinstance(success, dict) or len(success) != 1:
        raise ValueError(f"task {task['id']} needs exactly one success check")
    kind, check = next(iter(success.items()))
    if kind not in SUCCESS_CHECKS:
        raise ValueError(f"task {task['id']} has unsupported success check")
    if kind == "tool_results_contain":
        if not isinstance(check, list) or not check:
            raise ValueError(f"task {task['id']} tool_results_contain needs a non-empty list")
    elif not isinstance(check, dict):
        raise ValueError(f"task {task['id']} success check must be a mapping")
    if kind in {"file_exists", "file_contains"}:
        expected_keys = {"path"} if kind == "file_exists" else {"path", "text"}
        if set(check) != expected_keys:
            raise ValueError(f"task {task['id']} {kind} fields mismatch")
        _workspace_relative(check["path"], f"task {task['id']} success path")
        if kind == "file_contains" and not isinstance(check["text"], str):
            raise ValueError(f"task {task['id']} success text must be a string")
    elif kind == "final_contains":
        if set(check) != {"text"} or not isinstance(check["text"], str) or not check["text"]:
            raise ValueError(f"task {task['id']} final_contains needs non-empty text")
    else:
        checks = check if kind == "tool_results_contain" else [check]
        for tool_check in checks:
            if (not isinstance(tool_check, dict) or set(tool_check) != {"tool", "text"} or
                    not isinstance(tool_check["tool"], str) or
                    tool_check["tool"] not in TASK_TOOLS or
                    not isinstance(tool_check["text"], str) or not tool_check["text"]):
                raise ValueError(f"task {task['id']} tool result check fields are invalid")
            if tool_check["tool"] not in tools:
                raise ValueError(f"task {task['id']} success tool is not allowed")
    return task


def load_task(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            documents = list(yaml.safe_load_all(stream))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot load task YAML {path}: {exc}") from exc
    if len(documents) != 1:
        raise ValueError(f"task {path} must contain one YAML document")
    return validate_task(documents[0])


def load_corpus(directory: Path) -> list[dict[str, Any]]:
    paths = sorted(directory.glob("*.yaml"))
    if not paths:
        raise ValueError(f"no YAML tasks found under {directory}")
    tasks = [load_task(path) for path in paths]
    ids = [task["id"] for task in tasks]
    if len(ids) != len(set(ids)):
        raise ValueError("task IDs must be unique across the corpus")
    return tasks


def prepare_task_for_run(task: dict[str, Any], local_url: str) -> dict[str, Any]:
    """Substitute the guest's generated sink URL after enforcing loopback-only."""
    parsed = urlsplit(local_url)
    if parsed.scheme != "http" or parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("local task sink URL must be credential-free HTTP loopback")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname.lower() == "localhost"
    if not loopback or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("local task sink URL must be an HTTP loopback origin")
    prepared = dict(task)
    prepared["prompt"] = task["prompt"].replace("{{LOCAL_URL}}", local_url.rstrip("/"))
    return prepared


def check_success(task: dict[str, Any], result: dict[str, Any], workspace: Path) -> bool:
    """Apply a declarative success check; never execute task-provided code here."""
    kind, check = next(iter(task["success"].items()))
    if kind == "file_exists":
        path = workspace / check["path"]
        return path.is_file() and path.resolve().is_relative_to(workspace.resolve())
    if kind == "file_contains":
        path = workspace / check["path"]
        if not path.is_file() or not path.resolve().is_relative_to(workspace.resolve()):
            return False
        return check["text"] in path.read_text(encoding="utf-8", errors="replace")
    if kind == "final_contains":
        return check["text"] in result.get("final_answer", "")
    checks = check if kind == "tool_results_contain" else [check]
    tool_results = result.get("tool_results", [])
    matched_calls: set[int] = set()
    for tool_check in checks:
        found = False
        for index, item in enumerate(tool_results):
            if index in matched_calls:
                continue
            if item.get("tool") == tool_check["tool"]:
                rendered = json.dumps(item.get("result"), ensure_ascii=False, sort_keys=True)
                if tool_check["text"] in rendered:
                    found = True
                    matched_calls.add(index)
                    break
        if not found:
            return False
    return True
