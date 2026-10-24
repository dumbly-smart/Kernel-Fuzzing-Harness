# Phase 3: local model and benign corpus

## Implementation choices

- The task files are YAML mappings parsed with the pinned Ubuntu `python3-yaml`
  package. A single declarative success check is evaluated after every run.
- Runs use the Ollama local chat API on `127.0.0.1`; the runtime archive and
  downloaded model manifest are recorded separately from the base BPF guest
  lock. Seed, temperature, context size, output cap, and turn cap are explicit.
- The local HTTP fixtures are served only on guest loopback from a process kept
  outside the agent cgroup. This leaves the agent's connect and receive events
  attributable to the agent without counting the fixture server's own syscalls.
- Failed model calls remain in `runs.jsonl` with the exact error. They count as
  utility failures and are not silently retried against another model or API.

## First guest attempt

The fresh 6 GiB RAM / 32 GiB overlay passed repeated setup, `make check`, all 62
unit tests, Phase 1 tracer smoke, and the 10-task Phase 2 join smoke. Model
installation stopped before downloading a model because the script requested
the nonexistent `ollama-linux-amd64.tgz` URL and GitHub returned HTTP 404
(`curl` exit 22). The pinned SHA was for the official
`ollama-linux-amd64.tar.zst` asset. The asset name is now explicit in
`config/model.json`; the corrected installer verifies the same SHA before
extracting it. No model inference or corpus runs occurred in that attempt.

The second guest downloaded and checksum-verified the 1.4 GiB release asset,
extracted it, started the loopback service, and received a successful
`/api/version` health response. It then stopped because `/usr/local/bin/ollama
--version` exited with status 2. The installer captured that command's output
inside shell substitution, so its stderr was not preserved in the returned log;
the trap reported the failing command but not the captured text. The health
check showed the service was responding, so version verification now reads the
server's `/api/version` JSON field, which checks the process actually serving
requests. No model pull or corpus run occurred in this attempt either.

Two retries based on that intermediate guest were stopped before a result
handoff when host memory fell below 250 MiB and the host's 4 GiB swap was full;
their disposable overlays are preserved under `data/vm/guest-phase3c.qcow2`
and `guest-phase3d.qcow2`. Neither produced a result marker, so neither is an
acceptance run and no model/corpus measurements are inferred from them. The
next attempt uses a 4 GiB guest allocation to preserve host headroom. If the
8B model cannot load there, its concrete Ollama error and all 90 run outcomes
will be retained rather than silently changing the model.

A 4 GiB prepared-base attempt successfully reran environment discovery, then
failed its unprivileged BPF rebuild with `mkdir: cannot create directory
'../build': Permission denied`. The accepted base contained root-owned build
outputs from the setup step. Setup and the guest harness now transfer `build/`
to `ubuntu` before its check/test run. In the apt-independent path the base can
also lack `build/` entirely, so the harness now creates it with the test user's
ownership before changing existing outputs. This attempt did not reach model
installation.

After that ownership fix, the corrected 4 GiB guest ran Ollama installation
without returning its serial result bundle. The host kernel log identifies the
cause precisely: at 11:00 local time, a `tokio-rt-worker` allocation invoked
the global OOM killer, which killed `qemu-system-x86` (PID 173105) at 4,223,580
KiB anonymous RSS. The overlay reached 4.2 GB; no `TRIPWIRE_RESULT` marker was
written, so this run provides no model lock or corpus outcome. I will not repeat
that memory allocation. The host currently cannot safely complete the 8B model
path in this guest size; the next run will use an explicitly identified smaller
quantized Qwen3 profile in a 3 GiB guest, while retaining the 8B config as the
preferred research profile. Model size is a utility confound and will be written
into each corpus manifest.

The 1.7B constrained profile was then tried in a 3 GiB guest. It also produced
no result marker: at 11:21 local time the host kernel's global OOM killer killed
QEMU (PID 208076) at 3,164,716 KiB anonymous RSS. There was no corpus result to
recover. Larger-model execution cannot be claimed on this host. The next attempt
uses the separately pinned `config/model.tiny.json` Qwen3 0.6B Q4_K_M profile in
a 2 GiB guest; its smaller capacity is a major task-success confound, so success
rates and exact profile digest must accompany any behavior results.

Official pin source: <https://github.com/ollama/ollama/releases/expanded_assets/v0.40.7>.

## Acceptance

Pending a fresh guest run. Keep the exact model manifest digest, 90 task
outcomes, join metrics, dropped-event count, and behavior summaries with the
acceptance artifacts; do not fill these from expected values.
