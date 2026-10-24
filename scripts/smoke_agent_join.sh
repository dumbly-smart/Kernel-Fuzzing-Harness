#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo 'ERROR: agent join smoke must run as root inside the disposable guest' >&2
    exit 1
fi
if [[ ! -r /sys/kernel/btf/vmlinux || ! -d /sys/fs/cgroup ]]; then
    echo 'ERROR: BTF and cgroup v2 must be available in the guest' >&2
    exit 1
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
run_dir=$(mktemp -d "$repo_dir/data/phase2-smoke.XXXXXX")
cgroup_path="/sys/fs/cgroup/tripwire-agent-$$"
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
mkdir -p "$run_dir/workspaces"
python3 - "$run_dir" "$repo_dir/tasks/phase2_tasks.json" <<'PY'
import json
from pathlib import Path
import sys

run_dir = Path(sys.argv[1])
tasks = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
for task in tasks:
    workspace = run_dir / "workspaces" / task["id"]
    workspace.mkdir(parents=True)
    (workspace / "note.txt").write_text("Synthetic note for Tripwire.\n", encoding="utf-8")
    (workspace / "source.txt").write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    (workspace / "report.txt").write_text("Synthetic report.\n", encoding="utf-8")
PY

python3 -u - <<'PY' >"$run_dir/sink-port" 2>"$run_dir/sink.log" &
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("Tripwire local synthetic page: " + self.path + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

server = HTTPServer(("127.0.0.1", 0), Handler)
print(server.server_port, flush=True)
server.serve_forever()
PY
sink_pid=$!
for _ in $(seq 1 100); do
    [[ -s "$run_dir/sink-port" ]] && break
    sleep 0.05
done
if [[ ! -s "$run_dir/sink-port" ]]; then
    echo 'ERROR: local HTTP sink did not publish its port' >&2
    cat "$run_dir/sink.log" >&2
    exit 1
fi
sink_port=$(cat "$run_dir/sink-port")

python3 -m tripwire.cli --cgroup "$cgroup_path" \
    --output "$run_dir/events.jsonl" 2>"$run_dir/loader.log" &
tracer_pid=$!
for _ in $(seq 1 100); do
    if grep -q '^tripwire: attached ' "$run_dir/loader.log"; then
        break
    fi
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

# Moving this parent shell causes all task runner and tool subprocesses to
# inherit the same cgroup ID, so cgroup filtering includes the complete tree.
printf '%s\n' "$$" > "$cgroup_path/cgroup.procs"
CGROUP_PATH="$cgroup_path" SINK_URL="http://127.0.0.1:$sink_port" \
RUN_DIR="$run_dir" REPO_DIR="$repo_dir" bash -c '
    set -euo pipefail
    python3 - "$RUN_DIR" "$REPO_DIR/tasks/phase2_tasks.json" "$SINK_URL" <<"PY"
import json
from pathlib import Path
import sys

run_dir, task_path, sink_url = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
tasks = json.loads(task_path.read_text(encoding="utf-8"))
for task in tasks:
    for action in task["actions"]:
        for key, value in action["args"].items():
            if isinstance(value, str):
                action["args"][key] = value.replace("__SINK_URL__", sink_url)
    task_file = run_dir / (task["id"] + ".json")
    task_file.write_text(json.dumps(task), encoding="utf-8")
    workspace = run_dir / "workspaces" / task["id"]
    calls_file = run_dir / "calls.jsonl"
    result_file = run_dir / (task["id"] + ".results.json")
    import subprocess
    subprocess.run([
        sys.executable, "-m", "agent.run", "--task", str(task_file),
        "--workspace", str(workspace), "--call-log", str(calls_file),
        "--results", str(result_file), "--run-id", task["id"],
    ], cwd=run_dir.parents[1], check=True)
    results = json.loads(result_file.read_text(encoding="utf-8"))["results"]
    task_id = task["id"]
    for action_result in results:
        result = action_result["result"]
        if isinstance(result, dict) and "return_code" in result and result["return_code"] != 0:
            raise SystemExit(f"{task_id}: shell tool failed: {result}")
        if isinstance(result, dict) and "status" in result and result["status"] != 200:
            raise SystemExit(f"{task_id}: HTTP status was not 200")
print(f"task_success_count={len(tasks)}")
PY
'

sleep 1
kill -INT "$tracer_pid"
wait "$tracer_pid"
tracer_pid=
kill "$sink_pid" 2>/dev/null || true
wait "$sink_pid" 2>/dev/null || true
sink_pid=

python3 -m tripwire.join --events "$run_dir/events.jsonl" \
    --calls "$run_dir/calls.jsonl" --output "$run_dir/joins.jsonl" \
    --report "$run_dir/join-report.json" \
    --late-event-grace-ms "$(python3 -c 'import json; print(json.load(open("config/tripwire.json"))["late_event_grace_ms"])')"

# Preserve the complete evidence before assertions so a failing acceptance
# check can be diagnosed from the disposable guest's returned artifacts.
cp "$run_dir/events.jsonl" "$repo_dir/data/phase2-smoke.events.jsonl"
cp "$run_dir/calls.jsonl" "$repo_dir/data/phase2-smoke.calls.jsonl"
cp "$run_dir/joins.jsonl" "$repo_dir/data/phase2-smoke.joins.jsonl"
cp "$run_dir/join-report.json" "$repo_dir/data/phase2-smoke.join-report.json"

python3 - "$run_dir" <<'PY'
import json
from pathlib import Path
import sys

run_dir = Path(sys.argv[1])
calls = [json.loads(line) for line in (run_dir / "joins.jsonl").read_text().splitlines()]
report = json.loads((run_dir / "join-report.json").read_text())
task_count = len({call["call_id"].split(":", 1)[0] for call in calls})
empty_calls = [call["call_id"] for call in calls if not call["events"]]
if task_count != 10:
    raise SystemExit(f"expected 10 tasks in joined output, found {task_count}")
if empty_calls:
    raise SystemExit(f"tool calls without joined events: {empty_calls}")
if report["metrics"]["event_count"] == 0:
    raise SystemExit("tracer produced no events")
print(json.dumps({
    "task_count": task_count,
    "tool_call_count": len(calls),
    "calls_with_events": len(calls) - len(empty_calls),
    "total_syscall_events": report["metrics"]["event_count"],
    "assigned_events": report["metrics"]["assigned_events"],
    "orphan_events": report["metrics"]["orphan_events"],
    "orphan_event_rate": report["metrics"]["orphan_event_rate"],
    "ambiguous_events": report["metrics"]["ambiguous_events"],
}, sort_keys=True))
PY

echo "agent join artifacts: $run_dir"
