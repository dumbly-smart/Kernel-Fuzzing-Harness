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
    forwarding_result = runner(
        ["sysctl", "-n", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"],
        check=True, capture_output=True, text=True)
    forwarding_values = forwarding_result.stdout.splitlines()
    forwarding_off = forwarding_values == ["0", "0"]
    # UFW reports routed filtering as disabled when forwarding is off; verify
    # both kernel forwarding knobs instead of treating that display as a gap.
    routed_policy_ok = ("deny (routed)" in status or
                        ("disabled (routed)" in status and forwarding_off))
    status_requirements = ("Status: active", "deny (outgoing)",
                           "ALLOW IN", "ALLOW OUT", "on lo")
    if (any(item not in status for item in status_requirements) or
            not routed_policy_ok or not forwarding_off):
        raise RuntimeError(
            "UFW did not confirm loopback-only egress; refusing to run agent; "
            f"observed status:\n{status.rstrip()}\n"
            f"IPv4/IPv6 forwarding values: {forwarding_values!r}")
    return status
