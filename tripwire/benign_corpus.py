"""Resolve a complete Phase 3 corpus directory for detector training."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def _is_complete(directory: Path) -> bool:
    manifest_path = directory / "manifest.json"
    runs_path = directory / "runs.jsonl"
    joined_path = directory / "joined.jsonl"
    if not all(path.is_file() for path in (manifest_path, runs_path, joined_path)):
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        run_lines = runs_path.read_text(encoding="utf-8").splitlines()
        joined_lines = joined_path.read_text(encoding="utf-8").splitlines()
        runs = [json.loads(line) for line in run_lines]
        joined_calls = [json.loads(line) for line in joined_lines]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False

    if not isinstance(manifest, dict):
        return False
    counts = [manifest.get(key) for key in
              ("task_count", "seed_count", "run_count", "success_count")]
    if any(isinstance(value, bool) or not isinstance(value, int) for value in counts):
        return False
    task_count, seed_count, run_count, success_count = counts
    if (task_count < 1 or seed_count < 1 or run_count != task_count * seed_count or
            not 0 <= success_count <= run_count or len(runs) != run_count):
        return False

    seeds = manifest.get("seeds")
    if (not isinstance(seeds, list) or len(seeds) != seed_count or
            any(isinstance(seed, bool) or not isinstance(seed, int) for seed in seeds) or
            len(set(seeds)) != seed_count):
        return False

    run_ids = set()
    task_ids = set()
    task_seed_pairs = set()
    observed_successes = 0
    for run in runs:
        if not isinstance(run, dict):
            return False
        run_id, task_id = run.get("run_id"), run.get("task_id")
        task_type, seed, success = (run.get("task_type"), run.get("seed"),
                                    run.get("success"))
        if (not isinstance(run_id, str) or not run_id or
                not isinstance(task_id, str) or not task_id or
                not isinstance(task_type, str) or not task_type or
                isinstance(seed, bool) or not isinstance(seed, int) or seed not in seeds or
                not isinstance(success, bool) or run_id in run_ids or
                (task_id, seed) in task_seed_pairs):
            return False
        run_ids.add(run_id)
        task_ids.add(task_id)
        task_seed_pairs.add((task_id, seed))
        observed_successes += success
    if len(task_ids) != task_count or observed_successes != success_count:
        return False

    call_ids = set()
    for call in joined_calls:
        if not isinstance(call, dict):
            return False
        call_id = call.get("call_id")
        if not isinstance(call_id, str) or ":" not in call_id:
            return False
        run_id, counter = call_id.rsplit(":", 1)
        if (run_id not in run_ids or not counter.isascii() or not counter.isdigit() or
                call_id in call_ids):
            return False
        call_ids.add(call_id)
    return True


def resolve_benign_corpus(data_directory: Path,
                          explicit_directory: Path | None = None) -> Path:
    """Prefer an explicit or canonical path, otherwise use the newest complete run."""
    data_directory = Path(data_directory)
    if explicit_directory is not None:
        explicit_directory = Path(explicit_directory)
        if not _is_complete(explicit_directory):
            raise ValueError(
                "explicit benign corpus must contain a complete Phase 3 corpus "
                "(manifest.json, runs.jsonl, joined.jsonl): "
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
