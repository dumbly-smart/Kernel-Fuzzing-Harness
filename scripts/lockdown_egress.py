#!/usr/bin/env python3
"""Block all guest traffic except loopback before agent corpus/injection runs."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tripwire.egress import configure_loopback_only_egress


def main() -> int:
    if os.geteuid() != 0:
        print("ERROR: egress lockdown must run as root inside the disposable guest", file=sys.stderr)
        return 1
    if subprocess.run(["systemd-detect-virt", "--quiet"], check=False).returncode != 0:
        print("ERROR: no VM/container detected; refusing to change firewall", file=sys.stderr)
        return 1
    try:
        print(configure_loopback_only_egress(), end="")
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"ERROR: loopback-only egress setup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
