# Contributor and agent guide

This file is the practical working guide for people and coding agents changing
Tripwire. The uppercase [`AGENTS.md`](AGENTS.md) remains the short, authoritative
set of standing project rules; read both before making changes.

## Project in one paragraph

Tripwire measures which behaviors of a tool-using local agent can be inferred
from Linux OS telemetry. A CO-RE eBPF program observes metadata for selected
syscalls and process events in one cgroup v2 subtree. A deterministic local
agent logs tool-call windows. The collector and joiner relate those records,
then task-level baselines score held-out benign and controlled attack runs.
The research includes prompt-injection cases and an adaptive mimicry probe.
The attacker targets only the local agent and a loopback sink in a disposable
guest; results are research artifacts, not production security claims.

## Before changing anything

1. Read `AGENTS.md`, this guide, `README.md`, the relevant phase note under
   `docs/notes/`, and `docs/THREAT_MODEL.md`.
2. Check `git status --short --branch`. Preserve existing user changes. In
   particular, do not stage or overwrite unrelated `.gitignore` or `.ignore`
   edits.
3. Use the graft index first for code discovery. Use `graft ask` to understand
   a component, `graft grep` for all occurrences of a known symbol or literal,
   `graft callers` before changing a shared interface, and `graft skeleton`
   when you already know the file. Read source when graft marks coverage
   incomplete or the answer requires details outside the index.
4. Keep the work inside the disposable Ubuntu guest for kernel tracing, model
   runs, and all attack execution. The QEMU runner uses serial transfer and
   does not mount host directories. Never copy host credentials into a guest.
5. Use only fake credentials/canaries and the guest-local sink. Egress is
   denied for agent activity except loopback. Never target public services or
   systems outside the lab.

## Change and evidence rules

- Work in the phase relevant to the requested change. Do not imply an
  empirical acceptance result from unit tests, an offline fixture, or code
  inspection.
- Keep research parameters explicit in `config/` and copy their effective
  values into run manifests. Do not tune against held-out attack labels.
- Keep failed model/task runs in the data with their error and success flag.
  They are utility evidence, not rows to silently discard.
- Do not claim an attack was achieved unless its declarative goal check or
  local canary receipt confirms it. A detector positive on an unsuccessful
  attempt is not a successful attack detection.
- Preserve unverified facts as `TODO(verify)`; do not invent citations,
  versions, task outcomes, or metrics.
- Do not copy source from AgentSight, Tetragon, AgentDojo, or another project.
  Attribute ideas and cite sources in the writeup.
- Make small commits with one concern per commit. The project owner asked for
  pushes as well as commits; push completed commits to the configured remote
  when available. Never include unrelated worktree changes.

## Useful commands

Inside the pinned disposable guest:

```sh
make check                 # environment, shell syntax, Python compilation, BPF build
make test                  # unit tests
sudo make smoke-agent-join # tracer plus tool-call joining smoke
```

For a fresh isolated experiment, see `scripts/reproduce.sh` and the exact
resource/model options in `README.md` and `docs/ENVIRONMENT.md`. The runner
checks host `MemAvailable` before launch and during execution; do not bypass
that guard. Preserve failed overlays and logs for diagnosis. Repeated resource
failures are evidence that the current launcher cannot safely run that profile.

## Where changes belong

- Kernel event capture and event ABI: `bpf/`.
- Collection, parsing, validation, joining, and corpus handling: `tripwire/`.
- Agent loop, safe tool wrappers, tool-call JSONL: `agent/`.
- Detector models, features, dataset splitting, and metrics: `detectors/`.
- Orchestration and research output generation: `eval/` and `scripts/`.
- Attack definitions and adaptive plans: `injections/` and `attacker/`.
- Research parameters: `config/`.
- Long explanations and phase evidence: `docs/`, especially `docs/notes/`.
- Tests: `tests/`; BPF runtime smoke: `scripts/smoke_bpf.sh`.

## Reporting a completed slice

State what changed, how to run it, exactly which checks ran and their result,
known limits, and the next unresolved acceptance criterion. Link the relevant
phase note and keep implementation facts distinct from guest measurements.
