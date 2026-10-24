#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo 'ERROR: benign corpus smoke must run as root inside the disposable guest' >&2
    exit 1
fi
if [[ ! -r /sys/kernel/btf/vmlinux || ! -d /sys/fs/cgroup ]]; then
    echo 'ERROR: BTF and cgroup v2 must be available in the guest' >&2
    exit 1
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
model_config=${MODEL_CONFIG:-$repo_dir/config/model.json}
if [[ -n ${RUN_DIR:-} ]]; then
    run_dir=$RUN_DIR
    [[ ! -e $run_dir ]] || { echo "ERROR: run directory already exists: $run_dir" >&2; exit 1; }
    mkdir -p "$run_dir"
else
    run_dir=$(mktemp -d "$repo_dir/data/benign-corpus.XXXXXX")
fi
cgroup_path="/sys/fs/cgroup/tripwire-benign-$$"
tracer_pid=
sink_pid=

cleanup() {
    if [[ -n ${tracer_pid} ]]; then
        kill -INT "$tracer_pid" 2>/dev/null || true
        wait "$tracer_pid" 2>/dev/null || true
    fi
    if [[ -n ${sink_pid} ]]; then
        kill "$sink_pid" 2>/dev/null || true
        wait "$sink_pid" 2>/dev/null || true
    fi
    if [[ -d ${cgroup_path} ]]; then
        rmdir "$cgroup_path" 2>/dev/null || true
    fi
}
trap cleanup EXIT

mkdir "$cgroup_path"
python3 -m tripwire.local_sink --tasks "$repo_dir/tasks/benign" \
    --port-file "$run_dir/sink-port" >"$run_dir/sink.log" 2>&1 &
sink_pid=$!
for _ in $(seq 1 100); do
    [[ -s "$run_dir/sink-port" ]] && break
    sleep 0.05
done
if [[ ! -s "$run_dir/sink-port" ]]; then
    echo 'ERROR: local task sink did not publish its port' >&2
    cat "$run_dir/sink.log" >&2
    exit 1
fi
sink_port=$(cat "$run_dir/sink-port")

python3 -m tripwire.cli --cgroup "$cgroup_path" \
    --output "$run_dir/events.jsonl" 2>"$run_dir/loader.log" &
tracer_pid=$!
for _ in $(seq 1 100); do
    if grep -q '^tripwire: attached ' "$run_dir/loader.log"; then break; fi
    if ! kill -0 "$tracer_pid" 2>/dev/null; then
        cat "$run_dir/loader.log" >&2
        exit 1
    fi
    sleep 0.05
done
if ! grep -q '^tripwire: attached ' "$run_dir/loader.log"; then
    echo 'ERROR: tracer did not become ready' >&2
    cat "$run_dir/loader.log" >&2
    exit 1
fi

# Only the agent runner is moved into this cgroup. Ollama and the loopback sink
# remain separate services, so their own startup/file activity is not attributed.
printf '%s\n' "$$" > "$cgroup_path/cgroup.procs"
set +e
python3 -m eval.run_benign --task-dir "$repo_dir/tasks/benign" \
    --output-dir "$run_dir" --local-url "http://127.0.0.1:$sink_port" \
    --model-config "$model_config" --seeds 11 23 37 \
    >"$run_dir/runner.log" 2>&1
run_status=$?
set -e

sleep 1
kill -INT "$tracer_pid"
wait "$tracer_pid" || true
tracer_pid=
kill "$sink_pid" 2>/dev/null || true
wait "$sink_pid" 2>/dev/null || true
sink_pid=

python3 -m eval.summarize_benign --events "$run_dir/events.jsonl" \
    --calls "$run_dir/calls.jsonl" --runs "$run_dir/runs.jsonl" \
    --output-dir "$run_dir" >"$run_dir/summary.log"
python3 - "$run_dir" "$run_status" <<'PY'
import json
from pathlib import Path
import sys

run_dir = Path(sys.argv[1])
runner_status = int(sys.argv[2])
manifest = json.loads((run_dir / "manifest.json").read_text())
report = json.loads((run_dir / "corpus-summary.json").read_text())
if manifest["run_count"] != 90:
    raise SystemExit(f"expected 90 seeded task runs; recorded {manifest['run_count']}")
if runner_status:
    raise SystemExit(f"corpus runner exited {runner_status}; inspect {run_dir / 'runner.log'}")
print(json.dumps({
    "task_count": manifest["task_count"],
    "seed_count": manifest["seed_count"],
    "run_count": manifest["run_count"],
    "success_count": manifest["success_count"],
    "join_metrics": report["join_metrics"],
    "artifacts": str(run_dir),
}, sort_keys=True))
PY
echo "benign corpus artifacts: $run_dir"
