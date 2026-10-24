#!/usr/bin/env python3
"""Run seeded benign tasks against the configured loopback Ollama model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from agent.call_log import ToolCallLogger
from agent.react import DEFAULT_MODEL, OllamaClient, ReActAgent
from agent.tools import AgentTools
from tripwire.corpus import check_success, load_corpus, prepare_task_for_run
from tripwire.model_lock import model_lock_path, validate_model_lock


ROOT = Path(__file__).resolve().parents[1]


def _write_jsonl(stream, value: dict[str, Any]) -> None:
    stream.write(json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")
    stream.flush()


def run_corpus(*, task_dir: Path, output_dir: Path, seeds: list[int],
               local_url: str, model_config: dict[str, Any],
               model_lock: dict[str, Any]) -> list[dict[str, Any]]:
    tasks = load_corpus(task_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    validate_model_lock(model_config, model_lock)
    for name in ("runs.jsonl", "calls.jsonl", "manifest.json"):
        if (output_dir / name).exists():
            raise FileExistsError(f"refusing to overwrite previous corpus artifact: {output_dir / name}")
    model = model_config.get("model", DEFAULT_MODEL)
    base_url = model_config.get("base_url", "http://127.0.0.1:11434")
    generation = model_config["generation"]
    records = []
    run_path = output_dir / "runs.jsonl"
    calls_path = output_dir / "calls.jsonl"
    calls_path.touch()
    # Keep failures as rows; an unavailable local model must not erase utility data.
    with run_path.open("w", encoding="utf-8") as run_stream:
        for task in tasks:
            for seed in seeds:
                run_id = f"{task['id']}-seed-{seed}"
                workspace = output_dir / "workspaces" / run_id
                workspace.mkdir(parents=True, exist_ok=False)
                for relative, content in task["fixtures"].items():
                    fixture = workspace / relative
                    fixture.parent.mkdir(parents=True, exist_ok=True)
                    fixture.write_text(content, encoding="utf-8")
                record: dict[str, Any] = {
                    "run_id": run_id,
                    "task_id": task["id"],
                    "task_type": task["task_type"],
                    "seed": seed,
                    "model": model,
                    "success": False,
                    "agent_result": None,
                    "error": None,
                }
                try:
                    prepared = prepare_task_for_run(task, local_url)
                    client = OllamaClient(
                        base_url=base_url,
                        model=model,
                        seed=seed,
                        temperature=generation["temperature"],
                        context_tokens=generation["context_tokens"],
                        prediction_tokens=generation["prediction_tokens"],
                        timeout_seconds=generation["timeout_seconds"],
                    )
                    logger = ToolCallLogger(output_dir / "calls.jsonl", run_id=run_id)
                    agent_tools = AgentTools(workspace, logger)
                    result = ReActAgent(
                        client, agent_tools, max_turns=generation["max_turns"]
                    ).run(prepared)
                    record["agent_result"] = result
                    record["success"] = check_success(task, result, workspace)
                except Exception as exc:
                    record["error"] = {
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                _write_jsonl(run_stream, record)
                records.append(record)
                print(json.dumps({"run_id": run_id, "success": record["success"],
                                  "error": record["error"]}, sort_keys=True), flush=True)
    manifest = {
        "task_count": len(tasks),
        "seed_count": len(seeds),
        "run_count": len(records),
        "success_count": sum(record["success"] for record in records),
        "model": model,
        "model_runtime": model_config.get("runtime"),
        "model_lock": model_lock,
        "generation": generation,
        "seeds": seeds,
        "local_url": local_url,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-dir", type=Path, default=ROOT / "tasks/benign")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--local-url", required=True,
                        help="generated loopback fixture server origin")
    parser.add_argument("--model-config", type=Path, default=ROOT / "config/model.json")
    parser.add_argument("--model-lock", type=Path, default=None,
                        help="defaults to the lock file paired with --model-config")
    parser.add_argument("--seeds", type=int, nargs="+", default=[11, 23, 37])
    args = parser.parse_args(argv)
    if not args.seeds or len(args.seeds) != len(set(args.seeds)):
        parser.error("seeds must be a non-empty list of unique integers")
    try:
        model_config = json.loads(args.model_config.read_text(encoding="utf-8"))
        lock_path = args.model_lock or model_lock_path(args.model_config)
        model_lock = json.loads(lock_path.read_text(encoding="utf-8"))
        run_corpus(task_dir=args.task_dir, output_dir=args.output_dir,
                   seeds=args.seeds, local_url=args.local_url,
                   model_config=model_config, model_lock=model_lock)
    except Exception as exc:
        print(f"ERROR: benign corpus runner: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
