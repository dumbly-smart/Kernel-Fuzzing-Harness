"""Guest firewall setup for local-only model and injection experiments."""

from __future__ import annotations

import subprocess
from typing import Callable, Any


def configure_loopback_only_egress(
        runner: Callable[..., Any] = subprocess.run) -> str:
    """Reset UFW in a disposable guest and permit network traffic only on lo."""
    commands = (
        ["ufw", "--force", "reset"],
        ["ufw", "default", "deny", "incoming"],
        ["ufw", "default", "deny", "outgoing"],
        ["ufw", "default", "deny", "routed"],
        ["ufw", "allow", "in", "on", "lo"],
        ["ufw", "allow", "out", "on", "lo"],
        ["ufw", "--force", "enable"],
    )
    for command in commands:
        runner(command, check=True, capture_output=True, text=True)
    result = runner(["ufw", "status", "verbose"], check=True,
                    capture_output=True, text=True)
    status = result.stdout
    required = ("Status: active", "deny (outgoing)", "deny (routed)",
                "ALLOW IN", "ALLOW OUT", "on lo")
    if any(item not in status for item in required):
        raise RuntimeError("UFW did not confirm loopback-only egress; refusing to run agent")
    return status
