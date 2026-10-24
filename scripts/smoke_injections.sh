#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo 'ERROR: injection smoke must run as root inside the disposable guest' >&2
    exit 1
fi
if [[ ! -r /sys/kernel/btf/vmlinux || ! -d /sys/fs/cgroup ]]; then
    echo 'ERROR: BTF and cgroup v2 must be available in the guest' >&2
    exit 1
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
model_config=${MODEL_CONFIG:-$repo_dir/config/model.json}
benign_corpus=${BENIGN_CORPUS_DIR:-$repo_dir/data/phase3-corpus}
if [[ -n ${RUN_DIR:-} ]]; then
    run_dir=$RUN_DIR
    [[ ! -e $run_dir ]] || { echo "ERROR: run directory already exists: $run_dir" >&2; exit 1; }
    mkdir -p "$run_dir"
else
    run_dir=$(mktemp -d "$repo_dir/data/injection-corpus.XXXXXX")
fi
python3 "$repo_dir/scripts/lockdown_egress.py" >"$run_dir/egress-lockdown.log"
bash "$repo_dir/scripts/prepare_agent_user.sh" >"$run_dir/agent-account.log"
for required in runs.jsonl joined.jsonl; do
    [[ -s "$benign_corpus/$required" ]] || {
        echo "ERROR: benign detector training artifact is missing: $benign_corpus/$required" >&2
        exit 1
    }
done
chown -R tripwire-agent:tripwire-agent "$run_dir"
if ! curl --fail --silent http://127.0.0.1:11434/api/version >/dev/null; then
    echo 'ERROR: pinned local Ollama runtime is not ready before injection run' >&2
    exit 1
fi

cgroup_path="/sys/fs/cgroup/tripwire-injections-$$"
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
    --injections "$repo_dir/injections" --canary-receipts "$run_dir/canary-receipts.jsonl" \
    --port-file "$run_dir/sink-port" >"$run_dir/sink.log" 2>&1 &
sink_pid=$!
for _ in $(seq 1 100); do
    [[ -s "$run_dir/sink-port" ]] && break
    sleep 0.05
done
if [[ ! -s "$run_dir/sink-port" ]]; then
    echo 'ERROR: local injection sink did not publish its port' >&2
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

# Moving this shell moves only future agent children. The sink and tracer were
# started first and remain outside the measured cgroup.
printf '%s\n' "$$" > "$cgroup_path/cgroup.procs"
set +e
runuser -u tripwire-agent -- python3 -m eval.run_injections --cases-dir "$repo_dir/injections" \
    --output-dir "$run_dir" --local-url "http://127.0.0.1:$sink_port" \
    --model-config "$model_config" >"$run_dir/runner.log" 2>&1
runner_status=$?
set -e

sleep 1
kill -INT "$tracer_pid"
wait "$tracer_pid" || true
tracer_pid=
kill "$sink_pid" 2>/dev/null || true
wait "$sink_pid" 2>/dev/null || true
sink_pid=

python3 -m tripwire.join --events "$run_dir/events.jsonl" --calls "$run_dir/calls.jsonl" \
    --output "$run_dir/joined.jsonl" --report "$run_dir/join-report.json" \
    >"$run_dir/join.log"
python3 -m eval.finalize_injections --runs "$run_dir/runs.jsonl" \
    --joined "$run_dir/joined.jsonl" --output "$run_dir/summary.json" \
    >"$run_dir/finalize.log"
python3 -m eval.run_detectors --corpus-dir "$benign_corpus" \
    --attack-dir "$run_dir" --output-dir "$run_dir/detector-eval" \
    >"$run_dir/detector-eval.log"
python3 - "$run_dir" "$runner_status" <<'PY'
import json
from pathlib import Path
import sys

run_dir = Path(sys.argv[1])
runner_status = int(sys.argv[2])
manifest = json.loads((run_dir / "manifest.json").read_text())
summary = json.loads((run_dir / "summary.json").read_text())
if manifest["run_count"] != manifest["case_count"]:
    raise SystemExit(f"not every injection produced a run row: {manifest}")
if runner_status:
    raise SystemExit(f"injection runner exited {runner_status}; inspect {run_dir / 'runner.log'}")
print(json.dumps({
    "case_count": manifest["case_count"],
    "goal_success_count": summary["goal_success_count"],
    "by_taxonomy_hypothesis": summary["by_taxonomy_hypothesis"],
    "artifacts": str(run_dir),
}, sort_keys=True))
PY
echo "injection artifacts: $run_dir"
