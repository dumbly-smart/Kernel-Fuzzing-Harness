"""Resolve a complete Phase 3 corpus directory for detector training."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def _is_complete(directory: Path) -> bool:
    return all((directory / name).is_file() and (directory / name).stat().st_size > 0
               for name in ("runs.jsonl", "joined.jsonl"))


def resolve_benign_corpus(data_directory: Path,
                          explicit_directory: Path | None = None) -> Path:
    """Prefer an explicit or canonical path, otherwise use the newest complete run."""
    data_directory = Path(data_directory)
    if explicit_directory is not None:
        explicit_directory = Path(explicit_directory)
        if not _is_complete(explicit_directory):
            raise ValueError(
                "explicit benign corpus must contain non-empty runs.jsonl and joined.jsonl: "
                f"{explicit_directory}")
        return explicit_directory

    canonical = data_directory / "phase3-corpus"
    if _is_complete(canonical):
        return canonical

    candidates = [path for path in data_directory.glob("phase3-corpus-*")
                  if path.is_dir() and _is_complete(path)]
    if not candidates:
        raise ValueError(
            f"no complete benign corpus under {data_directory}; set BENIGN_CORPUS_DIR")
    return max(
        candidates,
        key=lambda path: (
            (path / "manifest.json").stat().st_mtime_ns
            if (path / "manifest.json").is_file() else path.stat().st_mtime_ns,
            str(path),
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path,
                        default=Path(__file__).resolve().parents[1] / "data")
    parser.add_argument("--explicit", type=Path,
                        default=Path(os.environ["BENIGN_CORPUS_DIR"])
                        if os.environ.get("BENIGN_CORPUS_DIR") else None)
    args = parser.parse_args(argv)
    try:
        print(resolve_benign_corpus(args.data_dir, args.explicit))
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
