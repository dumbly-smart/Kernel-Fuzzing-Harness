# Phase 2 implementation plan

**Goal:** correlate cgroup-scoped syscall and process events with logged tool
calls, including subprocess ancestry, overlapping calls and late events.

**Design:** `docs/superpowers/specs/2026-10-24-phase2-correlation-design.md`.

## Tasks

1. **Join core and regression tests** — implement timestamp/cgroup/PID-tree
   matching, late grace, ambiguity, orphan accounting and rendered JSONL.
   Verify overlaps, subprocesses, late events, orphan events, and PID ambiguity.
   Commit `feat: correlate trace events with tool calls`.
2. **Tool call logger and local tools** — implement call JSONL, workspace-limited
   file tools, shell, loopback HTTP, action-list runner, and tests for successful
   and failed calls. Commit `feat: log sandboxed agent tool calls`.
3. **Ten task fixtures and guest smoke** — create ten synthetic tasks, a local
   sink, cgroup/tracer runner, and join report; verify every task's calls render
   with events and report orphan rate. Commit `test: verify tool syscall joins in guest`.
4. **Docs and acceptance** — record observed counts, rules, failure cases,
   environment and exact tests; update README and commit `docs: record phase two correlation acceptance`.

## Verification

- Unit tests run with `make test` after each code task.
- Full guest run uses the pinned environment's `make check`, `make test`,
  existing BPF smoke, and `scripts/smoke_agent_join.sh`.
- No host BPF loading, real credentials, non-loopback traffic, or external model
  API use is permitted.
