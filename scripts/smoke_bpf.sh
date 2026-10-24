#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo 'ERROR: smoke test must run as root inside the disposable guest' >&2
    exit 1
fi
if [[ ! -r /sys/kernel/btf/vmlinux || ! -d /sys/fs/cgroup ]]; then
    echo 'ERROR: BTF and cgroup v2 must be available in the guest' >&2
    exit 1
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
run_dir=$(mktemp -d "$repo_dir/data/phase1-smoke.XXXXXX")
cgroup_path="/sys/fs/cgroup/tripwire-smoke-$$"
loader_pid=
sink_pid=

cleanup() {
    if [[ -n ${loader_pid} ]]; then
        kill -INT "$loader_pid" 2>/dev/null || true
        wait "$loader_pid" 2>/dev/null || true
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
mkdir -p "$run_dir/work"
python3 -c 'import socket,sys; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); s.listen(1); print(s.getsockname()[1],flush=True); c,_=s.accept(); c.recv(256); c.sendall(b"tripwire-local-sink-ok"); c.close(); s.close()' \
    >"$run_dir/sink-port" 2>"$run_dir/sink.log" &
sink_pid=$!
for _ in $(seq 1 100); do
    [[ -s "$run_dir/sink-port" ]] && break
    sleep 0.05
done
if [[ ! -s "$run_dir/sink-port" ]]; then
    echo 'ERROR: local sink did not publish its port' >&2
    cat "$run_dir/sink.log" >&2
    exit 1
fi
sink_port=$(cat "$run_dir/sink-port")

python3 -m tripwire.cli --cgroup "$cgroup_path" \
    --output "$run_dir/events.jsonl" 2>"$run_dir/loader.log" &
loader_pid=$!
for _ in $(seq 1 100); do
    if grep -q '^tripwire: attached ' "$run_dir/loader.log"; then
        break
    fi
    if ! kill -0 "$loader_pid" 2>/dev/null; then
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

CGROUP_PATH="$cgroup_path" WORK_PATH="$run_dir/work" SINK_PORT="$sink_port" \
bash -c '
    # Moving this shell once captures its descendants without tracking PIDs.
    printf "%s\n" "$$" > "$CGROUP_PATH/cgroup.procs"
    cd "$WORK_PATH"
    printf "tripwire smoke\n" > relative.txt
    cat relative.txt > /dev/null
    cat missing.txt > /dev/null 2>&1 || true
    mv relative.txt renamed.txt
    python3 - "$SINK_PORT" <<"PY"
import socket, sys
connection = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
connection.sendall(b"fake-canary-metadata-only")
assert connection.recv(128) == b"tripwire-local-sink-ok"
connection.close()
PY
    rm renamed.txt
    /bin/true
'

# Let process-exit and the final periodic loss report reach the ring buffer.
sleep 1
kill -INT "$loader_pid"
wait "$loader_pid"
loader_pid=
kill "$sink_pid" 2>/dev/null || true
wait "$sink_pid" 2>/dev/null || true
sink_pid=

PYTHONPATH="$repo_dir" python3 - "$run_dir/events.jsonl" <<'PY'
import collections
import json
import sys
from tripwire.events import iter_events
from tripwire.stats import validate_stats_cadence

with open(sys.argv[1], encoding="utf-8") as trace:
    events = list(iter_events(trace))
types = collections.Counter(event["type"] for event in events)
syscalls = collections.Counter(event["syscall"] for event in events
                               if event["type"] == "syscall")
required = {"execve", "openat", "connect", "sendto", "write", "unlinkat"}
missing = required - syscalls.keys()
if missing:
    raise SystemExit(f"missing expected syscalls: {sorted(missing)}")
if not any(name in syscalls for name in ("rename", "renameat", "renameat2")):
    raise SystemExit("missing expected rename syscall")
if not any(event["type"] == "syscall" and event["syscall"] == "openat"
           and event["return_code"] == -2 for event in events):
    raise SystemExit("missing expected failed openat return code -2")
if not types["process_fork"] or not types["process_exit"]:
    raise SystemExit("missing process fork/exit tracepoints")
stats = [event for event in events if event["type"] == "stats"]
if not stats:
    raise SystemExit("missing ring-buffer stats record")
validate_stats_cadence(events, stats[-1]["poll_interval_ms"])
summary = {
    "events": len(events),
    "event_types": dict(sorted(types.items())),
    "syscalls": dict(sorted(syscalls.items())),
    "dropped_events": stats[-1]["dropped_events"],
    "ring_buffer_bytes": stats[-1]["ring_buffer_bytes"],
    "path_bytes": stats[-1]["path_bytes"],
    "poll_interval_ms": stats[-1]["poll_interval_ms"],
    "sequence_last": events[-1]["sequence"],
}
print(json.dumps(summary, sort_keys=True))
PY

cp "$run_dir/events.jsonl" "$repo_dir/data/phase1-smoke.events.jsonl"
echo "event stream: $run_dir/events.jsonl"
