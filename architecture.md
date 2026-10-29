# Tripwire architecture

Tripwire is a research pipeline for comparing application-visible tool calls
with OS-visible behavior of a local tool-using agent. The program has no
enforcement mode: it records and scores behavior. Experiments run in a
disposable Ubuntu QEMU guest, and attack traffic is limited to fake canaries
and a loopback fixture server.

## System map

```text
task YAML / injection YAML
          |
          v
 local ReAct agent ---- tool-call JSONL (time window, pid, cgroup, args)
          |                                  |
          | file / shell / local HTTP        |
          v                                  v
  agent process tree -- cgroup v2 --> eBPF tracepoints
                                         |
                                  ring buffer events
                                         |
                                  userspace collector
                                         |
                    events + tool calls + process ancestry
                                         |
                                    joiner
                                         |
          runs / joined calls / corpus features / manifests
                                         |
                   detectors + threshold calibration
                         |             |
                   attack verdicts   FP causes
                         |
                taxonomy / ablations / plots
```

## Runtime boundary

`scripts/run_phase0_vm.py` creates a QEMU overlay from an accepted base disk,
generates cloud-init seed data, transfers a Git archive and generated task
fixtures to the guest, launches QEMU, and receives result files over the
serial channel. It does not mount the host workspace into the guest or pass
through host credentials. Run artifacts are stored under ignored `data/vm/`.
The live host-memory check requires available memory of at least twice the
configured guest RAM, both before boot and while the guest runs. This is a
conservative local safety guard, not proof that a model fits. KVM with the
host CPU model is the default acceleration mode. `--qemu-accel tcg` opts into
software emulation for hosts whose KVM path is unavailable; it is much slower
and is recorded in provenance because it can affect task utility and timing.

`scripts/setup_vm.sh` checks the disposable Ubuntu environment, installs
pinned system tools from the documented snapshot, records a lock, and prepares
the BPF build. `scripts/check_env.py` verifies OS, kernel, BTF, compiler,
libbpf, bpftool, and recorded versions. The exact environment and caveats are
in `docs/ENVIRONMENT.md`.

## Tracer and event transport

`bpf/tripwire.bpf.c` attaches to tracepoints and emits records through a BPF
ring buffer. It checks the configured target cgroup before recording. Cgroup
filtering follows descendants as they fork and avoids the gaps that a fixed
PID list would have. Events include common process identity (`pid`, `tgid`,
`ppid`, `uid`, `comm`, cgroup ID), monotonic and wall-clock timestamps, event
type, and event-specific metadata.

The current tracer covers syscall entry/exit pairs for `execve`, `execveat`,
`openat`, `connect`, `sendto`, `write`, `clone`, `fork`, `vfork`, `exit`,
`exit_group`, `unlinkat`, `renameat`, and `renameat2`; it also emits explicit
process fork/exit records. For syscall events it records the syscall name,
return code, relevant file path(s), directory/file descriptor, byte count,
and parsed IPv4/IPv6 address and port when available. It records metadata
only: no file contents, write buffers, HTTP bodies, or socket payloads are
copied. The ring-buffer loss counter is reported separately in `stats`
records. Inspect `bpf/event.h` for the ABI and `tripwire/events.py` for the
validated JSON event contract.

`bpf/loader.c` loads the CO-RE object, configures the target cgroup, polls the
ring buffer, and serializes records. `tripwire/events.py` parses and validates
records; malformed fields are errors, not silently accepted. The exact
tracepoint and verifier decisions are discussed in `docs/notes/phase1.md`.

## Agent and call logging

`agent/react.py` implements a small local ReAct loop using the configured
Ollama-compatible endpoint. `agent/tools.py` exposes a limited set of
workspace file, shell, and HTTP tools. HTTP targets are constrained to
loopback. The workspace and generated fixtures are isolated for each run.
`agent/call_log.py` writes one JSONL record per tool invocation with a
run-scoped call ID, tool and arguments, monotonic start/end timestamps,
caller/tool PIDs, parent PID, cgroup ID, outcome, and any error type.

`config/model*.json` pins runtime/model profile and generation settings;
associated lock files record downloaded model manifest and layer digests.
Failed model calls and failed task checks remain in the corpus. Model profile
and task utility are important confounds for every detector result.

## Joining tool calls to OS events

`tripwire/join.py` assigns each behavioral event to at most one tool call.
An event must share the call's cgroup, occur between its start and end plus a
configurable late-event grace (default 250 ms), and belong to the process
subtree rooted at the tool PID. Fork events form timestamped parent-child
edges; an edge is used only at or after its fork timestamp and within the same
cgroup to reduce PID-reuse mistakes. If multiple calls match, the nearest
process ancestor wins; an equal-distance tie is ambiguous. No matching call
means orphan. `stats` events are counted separately and excluded from the
behavioral orphan denominator.

This is a heuristic correlation, not kernel-level causality. Events that
escape the grace period, lack observed ancestry, reuse PIDs, or occur in
overlapping tool windows can be orphaned or ambiguous. Every join report
records counts and rates so this uncertainty remains visible. See
`docs/notes/phase2.md`.

## Corpus and features

`tasks/benign/*.yaml` define prompt, task type, allowed tools, success
condition, and local fixture data. `tripwire/corpus.py` validates definitions
and evaluates task success. Multi-result predicates require separate tool
results, so one result cannot satisfy two expected actions. `eval/run_benign.py`
executes runs; `eval/summarize_benign.py` groups behavior by task type and
reports stable/noisy paths, binaries, hosts, syscall counts, sequence lengths,
success, dropped events, and join quality.

`detectors/features.py` converts joined calls into sample-level sets and
ordered tool/syscall-class sequences. Paths are normalized to remove unique
workspace and generated corpus IDs. Feature extraction does not include the
tool's arguments in OS-only detector scores. Tool arguments are logged as
separate application-layer evidence and can be used in future cross-layer
work, but must not be described as kernel telemetry.

## Detectors and evaluation

`detectors/allowlist.py` fits per-task-type benign feature sets (paths,
binaries, hosts, and syscalls) and scores unseen features. `detectors/ngram.py`
fits an ordered n-gram model over tool/syscall-class tokens. `detectors/metrics.py`
selects thresholds from benign calibration scores for fixed target FPR values
(currently 1% and 5%) and computes confusion metrics. `detectors/dataset.py`
holds all runs of a task in the same partition, preventing repeated seeds of
the same task from leaking across train/calibration/test.

`eval/run_detectors.py` produces scores, thresholded attack verdicts, a result
summary, and a false-positive cause log. The optional prompt classifier is a
transparent keyword baseline (`detectors/prompt_classifier.py`); it is not an
OS detector. Detector configuration and ablation feature groups live under
`config/` and are copied to output summaries.

## Injection, mimicry, taxonomy, and ablations

`injections/` contains local YAML cases for out-of-scope reads, canary
exfiltration, process creation, out-of-workspace writes, semantic-only
poisoning/wrong edits, and an adapted AgentDojo-style case. The adapted case
does not claim to be a canonical AgentDojo benchmark run. `eval/run_injections.py`
executes cases, and finalization combines goal receipts, observed events,
classifier output, and detector scores.

`attacker/mimicry.py` implements deterministic shell-naive, one-call adaptive,
sequence-padded, and workspace-file-scope strategies. Each sends a fake
canary only to the local sink. The attacker is a controlled tool-wrapper
probe, not a trained attacker or an LLM takeover. `attacker/report.py` keeps
each strategy separate and reports both goal success and detector decisions.

`eval/taxonomy.py` labels only successful, calibrated cases. A successful case
is operationally OS-visible when an OS-only detector flags it; partially
visible when OS activity exists but its meaning is hidden or a detector misses
it; and OS-invisible when a successful semantic goal has no positive calibrated
OS-only verdict. Otherwise the label stays pending. `eval/run_ablations.py`
compares files-only, network-only, process-only, ordered-sequence, and combined
features. Combined score is the configured arithmetic mean of allowlist and
n-gram novelty scores. `eval/plot_ablations.py` makes a dependency-free SVG.

## Main entry points

| Goal | Entry point | Main output |
|---|---|---|
| Environment and BPF build | `make check` | version and compatibility checks |
| Unit checks | `make test` | parsing, joining, features, detectors, task logic |
| Tracer smoke | `sudo bash scripts/smoke_bpf.sh` | local JSONL trace and loss summary |
| Agent/join smoke | `sudo make smoke-agent-join` | calls, events, joined calls, join report |
| Benign corpus | guest Phase 3 runner | runs, calls, events, joined traces, summary |
| Injection suite | guest Phase 5 runner | attack runs, receipts, classifier/detector evidence |
| Mimicry suite | guest Phase 6 runner | per-strategy records, trace, receipt, verdicts |
| Evaluation | `ATTACK_DIR=... make eval-all` | detector metrics, FPs, taxonomy, ablations, SVG |
| Full reproduction | `bash scripts/reproduce.sh` | isolated phase outputs under `data/vm/` |

Run details and commands are in `README.md`; measured status is in
`progress.md` and `reports.md`.
