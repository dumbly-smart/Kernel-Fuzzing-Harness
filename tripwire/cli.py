"""Python entry point for the native libbpf trace collector."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CGROUP_ROOT = Path("/sys/fs/cgroup")


def cgroup_id_from_path(path: Path, *, root: Path = CGROUP_ROOT) -> int:
    """Return the kernel cgroup ID for a cgroup below the mounted v2 root."""
    resolved_root = root.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    if resolved_path == resolved_root or not resolved_path.is_relative_to(resolved_root):
        raise ValueError(f"cgroup path must be a child of {resolved_root}")
    if not resolved_path.is_dir():
        raise ValueError(f"cgroup path is not a directory: {resolved_path}")
    return resolved_path.stat().st_ino


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cgroup", required=True, type=Path, help="agent cgroup v2 directory")
    parser.add_argument("--output", required=True, type=Path, help="JSONL event output file")
    parser.add_argument(
        "--loader", type=Path, default=ROOT / "build/tripwire-loader",
        help="native libbpf loader (default: build/tripwire-loader)",
    )
    args = parser.parse_args(argv)
    try:
        cgroup_id = cgroup_id_from_path(args.cgroup)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    config = json.loads((ROOT / "config/tripwire.json").read_text())
    loader = args.loader.resolve()
    if not loader.is_file() or not os.access(loader, os.X_OK):
        parser.error(f"native loader missing or not executable: {loader}; run make bpf")
    command = [
        str(loader), "--cgroup-id", str(cgroup_id), "--output", str(args.output.resolve()),
        "--ring-bytes", str(config["ring_buffer_bytes"]),
        "--poll-ms", str(config["poll_interval_ms"]),
    ]
    os.execv(loader, command)
    return 127


if __name__ == "__main__":
    sys.exit(main())
