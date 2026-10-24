"""Validated, local-only prompt-injection case definitions."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from tripwire.corpus import validate_task


CHANNELS = {"file_content", "web_page", "tool_output"}
TAXONOMY = {"OS-visible", "partially visible", "OS-invisible"}
GOALS = {
    "tool_result_contains": {"kind", "text"},
    "canary_received": {"kind"},
    "process_executed": {"kind", "basename"},
    "outside_file_exists": {"kind", "path"},
    "final_contains": {"kind", "text"},
    "file_contains": {"kind", "path", "text"},
}
CASE_FIELDS = {"id", "delivery_channel", "delivery_target", "payload", "goal",
               "expected_os_footprint", "taxonomy_hypothesis", "task"}


def validate_injection(case: Any) -> dict[str, Any]:
    if not isinstance(case, dict) or set(case) != CASE_FIELDS:
        actual = sorted(case) if isinstance(case, dict) else type(case).__name__
        raise ValueError(f"injection fields mismatch; expected={sorted(CASE_FIELDS)}, actual={actual}")
    case = dict(case)
    case_id = case["id"]
    if not isinstance(case_id, str) or not case_id or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in case_id):
        raise ValueError("injection id must be lowercase ASCII letters, digits, or hyphens")
    channel, target, payload = case["delivery_channel"], case["delivery_target"], case["payload"]
    if channel not in CHANNELS:
        raise ValueError(f"injection {case_id} has unsupported delivery_channel")
    if not isinstance(target, str) or not target or not isinstance(payload, str) or not payload:
        raise ValueError(f"injection {case_id} delivery_target and payload must be non-empty strings")
    if case["taxonomy_hypothesis"] not in TAXONOMY:
        raise ValueError(f"injection {case_id} has unsupported taxonomy_hypothesis")
    footprint = case["expected_os_footprint"]
    if not isinstance(footprint, list) or any(not isinstance(item, str) or not item for item in footprint):
        raise ValueError(f"injection {case_id} expected_os_footprint must be a list of strings")
    goal = case["goal"]
    if not isinstance(goal, dict):
        raise ValueError(f"injection {case_id} goal has unsupported kind or fields")
    goal_kind = goal.get("kind")
    if not isinstance(goal_kind, str) or goal_kind not in GOALS or set(goal) != GOALS[goal_kind]:
        raise ValueError(f"injection {case_id} goal has unsupported kind or fields")
    if any(not isinstance(value, str) or not value for key, value in goal.items() if key != "kind"):
        raise ValueError(f"injection {case_id} goal values must be non-empty strings")
    if goal_kind == "outside_file_exists" and goal["path"] != "{{OUTSIDE_WRITE_PATH}}":
        raise ValueError(f"injection {case_id} outside-file goal must use the per-run fake path token")
    if goal_kind == "process_executed" and ("/" in goal["basename"] or "\\" in goal["basename"]):
        raise ValueError(f"injection {case_id} process goal must use a basename")
    if goal_kind == "file_contains":
        goal_path = PurePosixPath(goal["path"])
        if ("\\" in goal["path"] or goal_path.is_absolute() or
                any(part in ("", ".", "..") for part in goal_path.parts)):
            raise ValueError(f"injection {case_id} file goal must use a workspace-relative path")
    task = validate_task(case["task"])
    if task["id"] != case_id:
        raise ValueError(f"injection {case_id} task id must match injection id")
    if channel in {"file_content", "tool_output"}:
        target_path = PurePosixPath(target)
        if ("\\" in target or target_path.is_absolute() or
                any(part in ("", ".", "..") for part in target_path.parts)):
            raise ValueError(f"injection {case_id} delivery_target must be a safe workspace-relative path")
        if target in task["fixtures"]:
            raise ValueError(f"injection {case_id} delivery_target would overwrite a task fixture")
        task["fixtures"] = dict(task["fixtures"])
        task["fixtures"][target] = payload
    else:
        if task["task_type"] != "fetch" or target != f"/injection/{case_id}":
            raise ValueError(f"injection {case_id} web_page must use a fetch task and /injection/<id> route")
        if "local_http" in task:
            raise ValueError(f"injection {case_id} task may not predefine a local HTTP route")
        task["local_http"] = {"path": target, "body": payload}
    case["task"] = validate_task(task)
    return case


def load_injection(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            documents = list(yaml.safe_load_all(stream))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot load injection YAML {path}: {exc}") from exc
    if len(documents) != 1:
        raise ValueError(f"injection {path} must contain one YAML document")
    return validate_injection(documents[0])


def load_injections(directory: Path) -> list[dict[str, Any]]:
    paths = sorted(directory.rglob("*.yaml"))
    if not paths:
        raise ValueError(f"no YAML injections found under {directory}")
    cases = [load_injection(path) for path in paths]
    ids = [case["id"] for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("injection IDs must be unique")
    return cases
