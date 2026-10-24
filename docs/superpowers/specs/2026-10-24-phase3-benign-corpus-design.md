# Phase 3 design: benign corpus and local model

## Goal

Build a measured benign corpus of 30–100 YAML tasks, run each task three times
with distinct logged seeds, and retain per-run success, tool-call logs, OS
traces and workspace diffs. Report per-task-type paths, binaries, hosts,
sequence lengths and variability. Weak or failed model runs stay in the corpus
so model utility is not confused with detector quality.

## Model and runtime choice

Use a local-only Ollama server and Qwen3 8B Q4_K_M. The tag resolves to an
8.19B-parameter Q4_K_M model and is listed by Ollama as 5.2 GB with tool-call
support. Pin runtime v0.40.7 using its official Linux amd64 release SHA256 and
pin the pulled model by the local manifest digest in `config/model.lock.json`.
Generation parameters (seed, temperature, context and output-token cap) are
explicit task/run configuration. API requests go only to `127.0.0.1:11434`.
No cloud fallback is implemented.

## Components

- `agent/react.py`: small standard-library HTTP client and ReAct loop using
  Ollama's `/api/chat` tools protocol; validates tool names and task-level
  allowlists, logs each call through the Phase 2 logger, and caps turns/time.
- `config/model.json`: exact runtime/model identifiers and generation defaults;
  `config/model.lock.json`: SHA256 of the Ollama archive and model manifest/layers.
- `scripts/install_local_model.sh`: disposable-guest-only, checksummed runtime
  installation and model pull/verification.
- `tasks/benign/*.yaml`: 30 initial tasks across edit, search, tests, local fetch
  and document-summary task types. Each defines prompt, allowed tools, fixtures
  and a success check.
- `eval/run_benign.py`: run the corpus for three seeds, capture results and
  aggregate behavior summaries without dropping unsuccessful tasks.

## Safety and reproducibility

The model service listens on guest loopback only. URL tasks receive a local
server URL generated at run time; no task can supply an external host. File
tools remain workspace-bounded. Shell commands execute only within the
throwaway VM. The task runner records a failure if Ollama is unavailable or a
model digest does not match; there is no API fallback or silent model upgrade.

Initial acceptance uses a 32 GiB disposable overlay and 6 GiB guest memory for
the CPU-only 8B model. This is a test allocation, not a universal hardware
recommendation. If the guest cannot load the model, record the exact error and
task success as zero/failed rather than changing model or quantization without
updating the lock.

## Upstream pin sources

- Ollama release v0.40.7 and its amd64 archive checksum:
  <https://github.com/ollama/ollama/releases/tag/v0.40.7>.
- Ollama Qwen3 library entry and the `8b-q4_K_M` tag:
  <https://ollama.com/library/qwen3> and
  <https://registry.ollama.com/library/qwen3/tags>.
- Ollama's tool-call request/response format:
  <https://docs.ollama.com/capabilities/tool-calling> and
  <https://docs.ollama.com/api/chat>.
