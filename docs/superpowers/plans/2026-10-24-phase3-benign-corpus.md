# Phase 3 implementation plan

**Goal:** build a reproducible local-model benign corpus with 30 YAML tasks and
three seeded runs per task, retaining success and behavior traces.

**Design:** `docs/superpowers/specs/2026-10-24-phase3-benign-corpus-design.md`.

## Tasks

1. **Pin local model/runtime** — install checksummed Ollama v0.40.7 inside the
   disposable guest, pull Qwen3 8B Q4_K_M, record the complete manifest digest,
   and verify CPU inference at a fixed seed. Commit runtime/model config and lock.
2. **ReAct harness** — write tests for tool response parsing, local endpoint
   enforcement, allowed-tool enforcement, seed propagation, turn caps and call
   logging; implement the standard-library Ollama client and harness.
3. **Benign task corpus** — add 30 YAML tasks across five types with fixtures
   and explicit success checks; parser tests cover valid and malformed task
   records.
4. **Corpus runner and summaries** — run 3 seeds per task in the guest, retain
   every run including failures, and summarize stable/noisy paths, binaries,
   hosts and sequence lengths. Commit raw large traces ignored; commit small
   summary/sample artifacts.
5. **Acceptance and notes** — update the guest runner to provision the larger
   model overlay, run checks, record exact model/runtime locks and results, and
   document limits and learning materials.

## Verification

- New behavior gets failing tests before implementation.
- `make test` and shell/static checks run before commit.
- Model install, inference, BPF tracing and task corpus runs occur only in the
  disposable Ubuntu guest with loopback HTTP fixtures.
- Acceptance records all 90 runs, including task failures and zero-drop status.
