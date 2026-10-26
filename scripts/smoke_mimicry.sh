#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]] || ! systemd-detect-virt --quiet; then
    echo 'ERROR: mimicry smoke must run as root inside the disposable guest' >&2
    exit 1
fi
if [[ ! -r /sys/kernel/btf/vmlinux || ! -d /sys/fs/cgroup ]]; then
    echo 'ERROR: BTF and cgroup v2 must be available in the guest' >&2
    exit 1
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
benign_corpus=$(PYTHONPATH="$repo_dir" python3 -m tripwire.benign_corpus \
    --data-dir "$repo_dir/data")
if [[ -n ${RUN_DIR:-} ]]; then
    run_dir=$RUN_DIR
    [[ ! -e $run_dir ]] || { echo "ERROR: run directory already exists: $run_dir" >&2; exit 1; }
    mkdir -p "$run_dir"
else
    run_dir=$(mktemp -d "$repo_dir/data/mimicry.XXXXXX")
fi
printf '%s\n' "$benign_corpus" >"$run_dir/benign-corpus-path.txt"
for required in runs.jsonl joined.jsonl; do
    [[ -s "$benign_corpus/$required" ]] || {
        echo "ERROR: benign detector training artifact is missing: $benign_corpus/$required" >&2
        exit 1
    }
done
python3 "$repo_dir/scripts/lockdown_egress.py" >"$run_dir/egress-lockdown.log"
bash "$repo_dir/scripts/prepare_agent_user.sh" >"$run_dir/agent-account.log"
chown -R tripwire-agent:tripwire-agent "$run_dir"

cgroup_path="/sys/fs/cgroup/tripwire-mimicry-$$"
sink_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["loopback_sink_port"])' \
    "$repo_dir/config/lab.json")
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
    --canary-receipts "$run_dir/canary-receipts.jsonl" --port "$sink_port" \
    --port-file "$run_dir/sink-port" >"$run_dir/sink.log" 2>&1 &
sink_pid=$!
for _ in $(seq 1 100); do
    [[ -s "$run_dir/sink-port" ]] && break
    sleep 0.05
done
[[ -s "$run_dir/sink-port" ]] || { cat "$run_dir/sink.log" >&2; exit 1; }

python3 -m tripwire.cli --cgroup "$cgroup_path" \
    --output "$run_dir/events.jsonl" 2>"$run_dir/loader.log" &
tracer_pid=$!
for _ in $(seq 1 100); do
    if grep -q '^tripwire: attached ' "$run_dir/loader.log"; then break; fi
    if ! kill -0 "$tracer_pid" 2>/dev/null; then cat "$run_dir/loader.log" >&2; exit 1; fi
    sleep 0.05
done
grep -q '^tripwire: attached ' "$run_dir/loader.log" || {
    echo 'ERROR: tracer did not become ready' >&2; cat "$run_dir/loader.log" >&2; exit 1;
}

printf '%s\n' "$$" > "$cgroup_path/cgroup.procs"
set +e
runuser -u tripwire-agent -- python3 -m attacker.mimicry \
    --output-dir "$run_dir" --local-url "http://127.0.0.1:$sink_port" \
    --receipts "$run_dir/canary-receipts.jsonl" >"$run_dir/runner.log" 2>&1
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
python3 -m eval.run_detectors --corpus-dir "$benign_corpus" \
    --attack-dir "$run_dir" --output-dir "$run_dir/detector-eval" \
    >"$run_dir/detector-eval.log"
PYTHONPATH="$repo_dir" python3 - "$run_dir" "$runner_status" <<'PY'
import json
from pathlib import Path
import sys

from attacker.report import summarize_campaign

run_dir = Path(sys.argv[1])
runner_status = int(sys.argv[2])
runs = [json.loads(line) for line in (run_dir / "runs.jsonl").read_text().splitlines() if line]
if runner_status:
    raise SystemExit(f"mimicry runner exited {runner_status}; inspect {run_dir / 'runner.log'}")
if not all(row["goal_achieved"] is True for row in runs):
    raise SystemExit("one or more fake-canary goals were not received by the local sink")
verdicts = [json.loads(line) for line in
            (run_dir / "detector-eval/attack-verdicts.jsonl").read_text().splitlines() if line]
report = summarize_campaign(runs, verdicts)
(run_dir / "mimicry-summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps(report, sort_keys=True))
PY
echo "mimicry artifacts: $run_dir"
