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
- Corpus discovery requires a valid Phase 3 manifest and checks that its
  task/seed/run/success counts match the JSONL rows, every task has one row per
  declared seed, and joined calls refer to known unique run IDs. An empty
  `joined.jsonl` is valid when all runs made zero tool calls; a partial or
  malformed run file is skipped instead of selected as the newest corpus.

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

Two 2 GiB attempts for the 0.6B fallback did not produce measurements. The
first launcher session exited before QEMU wrote serial output. The next boot
reached about 915 MiB QEMU RSS while host available memory was 1.3 GiB and the
host's 4 GiB swap was full; I sent SIGTERM before model loading to avoid another
host-wide OOM. The runner reported `RuntimeError: guest returned no result; see
data/vm/serial.log`. Neither overlay is an acceptance run, and no model pull or
task outcome is inferred from it. Run this profile only when the host has enough
free memory headroom; the local development host is currently unsuitable for
model execution.

Official pin source: <https://github.com/ollama/ollama/releases/expanded_assets/v0.40.7>.

A later retry used a fresh overlay and passed the repository ownership check,
but host `MemAvailable` fell below the launch policy during the run (2,762 MiB
available for a 2,048 MiB guest, with 4,096 MiB required). I terminated that
QEMU process before host memory fell further. The runner then reported
`RuntimeError: guest returned no result; see data/vm/serial.log`; no model or
corpus outcome was recovered. The runner now rechecks the same 2x headroom
policy every two seconds while QEMU is active and stops the guest if it falls
below the threshold.

The runtime guard was exercised on a fresh 1,536 MiB guest. It stopped QEMU
when `MemAvailable` reached 3,035 MiB, below the 3,072 MiB requirement, and
reported `RuntimeError: host memory headroom fell below 3072 MiB during guest
run; MemAvailable=3035 MiB; need at least 3072 MiB (2x guest RAM)`. This
prevented further host memory pressure, but the guest did not return a result
bundle; this attempt also contributes no model or task measurements.

## Measured tiny-profile run

A fresh overlay backed by the preserved model guest completed the VM acceptance
path with the pinned `qwen3:0.6b-q4_K_M` profile (Ollama 0.40.7, model manifest
SHA256 `6f76d4346c34ba89df6e137fb661b4bb4daf322c1151b6ef0dfda981070a851f`).
It produced 90 run records for 30 tasks and seeds 11, 23, and 37, with no
runner-level exceptions. The model completed the task goal in 15/90 runs:
edit 9/18, summarize 6/18, and fetch, search, and tests 0/18 each. Most failed
edits attempted `file_write` with an object where the tool schema requires a
string; fetch/search/tests mostly made no tool calls. Treat the 16.7% aggregate
success rate as a severe utility confound. This corpus records the requested
outcomes, but it is not a sound broad task-type benign baseline.

The first join report counted tracer `stats` snapshots as orphan behavior. The
joiner now reports these separately and computes the orphan rate over behavioral
events only. Offline reprocessing of this run found 2,675 stats records, 1,218
behavioral events, 174 assigned events, 1,044 orphan events (85.71%), zero
ambiguous events, and zero dropped events. This remaining orphan rate is high;
the corrected report and derived JSONL files are under the ignored
`data/vm/phase3-resummarized/` directory. Recompute them with:

```sh
PYTHONPATH=. python3 eval/summarize_benign.py \
  --events data/vm/phase3-events.jsonl \
  --calls data/vm/phase3-calls.jsonl \
  --runs data/vm/phase3-runs.jsonl \
  --output-dir data/vm/phase3-resummarized
```

## Acceptance

The run and required per-task summary were produced, but Phase 3 remains
research-pending: the tiny model has poor utility and the behavior-event orphan
rate is high. Do not use it to support attack-detection claims without clearly
reporting these confounds. A more capable local model run is still needed for a
representative benign corpus.

## 1.7B profile attempts (2026-10-26)

Three additional runs used the pinned `config/model.low-memory.json` profile
(`qwen3:1.7b`), each on a fresh overlay from the cached provisioned guest.
None produced exported corpus results:

- At 2,048 MiB RAM + 3,072 MiB guest swap, the live host guard stopped the
  guest at `MemAvailable=4044 MiB; need at least 4096 MiB (2x guest RAM)`.
- At 1,536 MiB RAM + 3,072 MiB guest swap, it stopped at
  `MemAvailable=2917 MiB; need at least 3072 MiB (2x guest RAM)`.
- At 1,024 MiB RAM + 3,072 MiB guest swap, the guest remained CPU- and
  disk-active for 13m17s without returning a result. I stopped it when the
  host filesystem reached 9.5 GiB free (99% used); QEMU had cumulatively
  written 28,837,105,664 bytes and its overlay occupied 6.7 GiB. The runner
  reported `KeyboardInterrupt` while waiting; no corpus artifact was exported.

All three overlays and logs remain under ignored `data/vm/` for inspection.
No task or attack metrics can be attributed to these runs. Further VM runs
need stable host memory headroom and more free host storage; the measured
0.6B corpus remains the only completed Phase 3 dataset.

## Task definitions added after the measured corpus

The repository now has 34 benign task definitions, including three mixed
fetch tasks that read `notes/brief.txt` and fetch distinct loopback routes, and
one task that fetches the same page three times. Their success checks require
each declared tool result from a distinct call. The recorded 90-run corpus
predates these additions and still covers the earlier 30-task definition set;
do not present its metrics as measurements of the new tasks. A fresh Phase 3
run is required to measure their success and behavior.

## Bounded TCG diagnostics (2026-10-29)

The TCG fallback completed a one-task artifact-handoff diagnostic from the
cached model overlay using `config/model.tcg-diagnostic.json` and its paired
lock. The guest verified Ollama 0.40.7 and `qwen3:0.6b-q4_K_M`, reached the
corpus runner, and returned a complete bundle. Task `edit-01`, seed 11, failed
with `local Ollama chat request failed: timed out` under the profile's
900-second request timeout (0/1 successful). Its 399 behavioral syscall events
had no tool calls and were all orphaned; this reflects the failed task's
missing call record and is not join-quality evidence.

Further runs tested whether additional guest RAM or a smaller context could
help, but were stopped by the host's live 2x-RAM guard before a task result was
returned:

- 2,048 MiB guest: booted, then stopped at
  `MemAvailable=4019 MiB; need at least 4096 MiB`.
- 1,536 MiB guest: reached the corpus stage, then stopped at
  `MemAvailable=3019 MiB; need at least 3072 MiB`.
- 1,024 MiB guest with `config/model.tcg-lowcontext.json` (512-token context,
  same model/runtime pin): reached the corpus stage, then stopped at
  `MemAvailable=2020 MiB; need at least 2048 MiB`.

None of these three attempts returned the result metadata marker, task rows,
or a complete artifact bundle. They add no utility, behavior, or detector
measurements. The low-context profile is preserved for reproducibility, but
its effect on model output remains unknown. The 1 GiB diagnostic profile and
this profile are troubleshooting configurations, not substitutes for the
research model or corpus. Phase 3 remains pending until a host can sustain the
guest memory guard and return complete results.
