# Phase 2 design: tool-call correlation

## Goal

For every tool call, persist a JSONL record with a stable call ID, tool and
arguments, monotonic start/end times, caller/tool PID and TGID, and cgroup ID.
Join the trace stream to these calls and produce inspectable call-to-event
records plus orphan and ambiguous-event counts. Exercise ten deterministic
tasks in the disposable guest. The deterministic driver keeps Phase 2
reproducible; selecting and pinning an Ollama model/runtime is deferred until
the interactive local-model adapter is added, before model-dependent corpus
work.

## Components

- `agent/tools.py`: small, explicit `read_file`, `write_file`, `shell`, and
  `http_get` tools rooted in a task workspace. Shell is available only inside
  the throwaway guest. HTTP tasks are constrained to a loopback server.
- `agent/call_log.py`: append one JSON object per tool call, flush before and
  after execution, preserve errors, and record caller and executed PID/TGID.
- `agent/run.py`: execute a JSON action list through the same wrappers used by
  a later local-model ReAct policy. No paid API or external service is used.
- `tripwire/join.py`: validate logs, construct parent-child PID edges from
  `process_fork` records, and associate events with call windows.
- `scripts/smoke_agent_join.sh`: start the tracer for one cgroup and run ten
  local-only task fixtures in that cgroup; save a join report and trace summary.

## Join rules

1. Event timestamps use kernel/userspace monotonic nanoseconds; tool times use
   `time.monotonic_ns()`. Sequence numbers remain the stream delivery order.
2. An event is a candidate for call C when `call.start <= event.monotonic <=
   call.end + late_event_grace_ms`, event cgroup IDs match, and the event PID is
   the recorded tool PID or a descendant reachable through fork edges.
3. When exactly one call matches, attach the event there. When more than one
   distinct call matches (for example, overlapping inline calls in one PID),
   mark the event ambiguous and do not guess. With no match, count it as an
   orphan. A single event is never duplicated across calls.
4. The grace interval is a config value and captures short-lived events from a
   tool's child process after the wrapper returns. Events beyond the grace
   interval are orphaned. A call whose process exits before a late kernel event
   can still match through its PID and fork ancestry.
5. PID reuse within one trace can make ancestry ambiguous. The implementation
   will constrain ancestry to fork timestamps at or before the event and report
   multiple matches as ambiguous; a future run identity can strengthen this.

## Safety and limits

Task fixtures use synthetic text and a guest-local HTTP sink. The harness does
not read credentials or contact external destinations. The Phase 2 driver uses
predefined action plans rather than claiming LLM behavior. The syscall join
shows process/time correlation, not semantic causality: a tool may cause async
work that outlives the configured grace period or shares a process with another
overlapping tool.
