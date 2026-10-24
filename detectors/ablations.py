"""Feature projections used by the Phase 7 OS-signal ablation study."""

from __future__ import annotations

from typing import Any


PROCESS_SYSCALLS = {"execve", "execveat", "clone", "clone3", "fork", "vfork"}
NETWORK_SYSCALLS = {"connect", "sendto", "write"}
ABLATIONS = {"files", "network", "process", "sequence", "combined"}


def project_features(sample: dict[str, Any], ablation: str) -> dict[str, list[str]]:
    """Keep only one OS signal family; sequence means ordered tool/syscall tokens."""
    if ablation not in ABLATIONS:
        raise ValueError(f"unknown ablation: {ablation}")
    source = sample.get("features", {})
    result = {key: [] for key in ("paths", "binaries", "hosts", "syscalls", "sequences")}
    if ablation == "files":
        result["paths"] = list(source.get("paths", []))
    elif ablation == "network":
        result["hosts"] = list(source.get("hosts", []))
        result["syscalls"] = [value for value in source.get("syscalls", [])
                               if value in NETWORK_SYSCALLS]
    elif ablation == "process":
        result["binaries"] = list(source.get("binaries", []))
        result["syscalls"] = [value for value in source.get("syscalls", [])
                               if value in PROCESS_SYSCALLS]
    elif ablation == "sequence":
        result["sequences"] = list(source.get("sequences", []))
    else:
        for key in result:
            result[key] = list(source.get(key, []))
    return result
