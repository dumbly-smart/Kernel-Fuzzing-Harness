# Phase 2: tool-call correlation

## What was built

`agent/` now provides workspace-bounded file read/write tools, a Bash shell
tool, and an HTTP GET tool restricted to loopback destinations. Each call is
logged to JSONL with a stable call ID, tool, arguments, monotonic start/end,
caller and tool PID/TGID/PPID, cgroup ID, and success/error type. Results are
returned to the driver but are not copied into the call log.

`tripwire.join` attaches each event to at most one call when cgroup, time window,
and process ancestry agree. Fork events add parent/child PID edges. The
configurable 250 ms late-event grace is in `config/tripwire.json`. The joiner
prefers the call whose tool PID is closest to an event PID; a tie at that
distance is marked ambiguous. No matching call is an orphan. The command emits
one JSONL record per tool call and a JSON report with assigned, orphan and
ambiguous counts/rates.

The ten fixture plans in `tasks/phase2_tasks.json` are deterministic action
lists, not LLM-generated behavior. The runner uses the same tool wrappers that
a local-model ReAct policy can call later. The local HTTP server binds only to
`127.0.0.1`. No model runtime or weights have been installed or pinned yet, so
these runs measure correlation only.

## How to run

In the pinned disposable Ubuntu guest, with the BPF-capable tools installed:

```sh
make check
make test
sudo make smoke-agent-join
```

The smoke creates a temporary cgroup and workspaces, starts the tracer, runs
the ten task fixtures, joins the trace and call log, and validates that every
call has at least one event. A local loopback server answers both HTTP tasks.
The last run's event trace, call log, join output and report are saved under
ignored `data/vm/` artifacts by the QEMU acceptance runner.

## Acceptance result

On 2026-10-24, the disposable Ubuntu 24.04 amd64 guest passed `make check`, 43
Python tests, the Phase 1 tracer smoke and the ten-task Phase 2 smoke. All 10
tasks succeeded and all 11 tool calls received events. The joiner assigned 428
of 2,209 records, marked 1,781 as orphans (80.62%), and marked none ambiguous.
The final collector records reported zero ring-buffer drops. Configuration was
250 ms late-event grace, 16 MiB ring, and 1,000 ms stats cadence.

Most orphan records were from Python processes outside tool-call windows
(1,700 events: 1,681 syscalls, 14 fork records, and 5 exit records); 47 were
from the cgroup supervisor's Bash process, 31 from its `sleep` helper, and 3
were collector stats records. These events are retained and counted rather
than guessed into tool windows.
This high orphan rate is a measured property of the current short-lived,
one-process-per-task driver; it is not a detection result.

The first end-to-end attempt marked a shell call ambiguous because its PID was
both a descendant of the preceding agent PID (still inside that call's grace
window) and the exact PID of the current shell tool. Choosing the shortest PID
ancestry distance resolved the ownership. Same-process overlapping calls still
remain ambiguous by design.

## Known limits

- The task driver executes predefined tool actions; it is not a ReAct agent and
  does not measure local-model utility. Pin an Ollama build and model digest,
  quantization, and sampling parameters before model-dependent corpus runs.
- Orphan rate includes process startup and collector/supervisor events. Later
  evaluation should preserve this raw metric while also reporting causes and
  task-only slices.
- PID reuse can confuse ancestry within a long trace; current fork edges are
  time-bounded but do not carry kernel process start IDs.
- The 250 ms grace may be too short for intentionally detached work and may
  create overlap with a following call. It remains a visible config choice.
- Shell confinement relies on the disposable guest boundary. The file tools
  themselves reject absolute paths, `..` escapes, and symlink escapes.

## What to learn

- `clock_gettime(2)`, CLOCK_MONOTONIC: use one monotonic clock for userspace
  windows and kernel event timestamps.
- `cgroups(7)` and `proc_pid_cgroup(5)`: process membership inheritance and
  how a process discovers its current cgroup path.
- Linux kernel docs, “Control Group v2”, §Organizing Processes and §Delegation:
  <https://docs.kernel.org/admin-guide/cgroup-v2.html>.
