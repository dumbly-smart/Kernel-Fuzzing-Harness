# Implementation progress

Status is split between code present in the repository and experiments that
have produced usable evidence. “Implemented” does not mean the research
acceptance criterion is met.

## Phase status

| Phase | Implementation | Evidence / acceptance status |
|---|---|---|
| 0 — scaffold and environment | VM setup, environment checks, pinned lock and reproduction entry point exist. | Accepted disposable QEMU guest on 2026-10-22. Host checks are not a substitute; this Arch development host is intentionally rejected by Ubuntu-only checks. |
| 1 — eBPF tracer | CO-RE tracepoint programs, cgroup filter, ring buffer, loader, JSON events and loss stats exist. | Guest tracer smoke accepted 2026-10-24. See `docs/notes/phase1-guest-acceptance.txt`. |
| 2 — correlation | Tool-call JSONL, process ancestry join, 250 ms late-event grace, and orphan/ambiguous reporting exist. | Ten-task guest smoke accepted. Historical Phase 3 joins still had 85.71% behavioral orphan rate. |
| 3 — benign corpus | 34 task definitions now exist; three seeds and multiple pinned local model profiles are supported. | Only an older 30-task / 90-run corpus is measured. Tiny 0.6B profile succeeded on 15/90 tasks; four added tasks are unmeasured. Fresh corpus needed. |
| 4 — detectors | Per-task-type allowlist, tool/syscall n-grams, held-out task split, FPR thresholds and FP-cause output exist. | Historical small-corpus metrics are generated; low utility and small calibration sets limit interpretation. |
| 5 — injection suite | Seven local YAML cases, fake canary sink, goal recording, keyword classifier and detector integration exist. | Historical run completed seven cases but reached zero goals. No successful injection evidence; taxonomy remains pending. |
| 6 — adaptive mimicry | Four deterministic profiles and per-strategy reporting exist. | Historical guest run measured two earlier profiles only. New padding/scope profiles have not been evaluated against a corpus containing their matching tasks. |
| 7 — taxonomy and ablations | Operational taxonomy, five feature ablations, metrics and SVG plot generation exist. | Historical outputs generated. All seven taxonomy cases were pending because their goals failed; blocking utility is not measured. |
| 8 — release and writeup | README, license, VM reproduction script, environment/threat-model docs and paper skeleton exist. | Clean fresh-launcher reproduction with successful injections and refreshed Phase 3/6 evidence remains open. |

Detailed phase records are in `docs/notes/phase0.md` through
`docs/notes/phase8.md`. The workshop draft is `docs/paper/WORKSHOP_DRAFT.md`.

## Current corpus and campaign mismatch

The current benign task directory contains 34 YAML definitions. The 90-run
historical dataset predates four of them (three mixed file-read/fetch tasks and
one three-fetch task). Consequently, the current task code can build more
matched behavior profiles than the historical benign data can validate. The
historical fetch task type had no successful tool calls, which means its
observed “benign envelope” is empty for HTTP behavior. The measured one-call
adaptive profile therefore was not shown to mimic a functioning benign fetch.

The saved Phase 6 manifest and summary contain two deterministic runs. They
predate the sequence-padded and workspace-file-scope profiles. Do not quote
those two runs as results for all four current strategies.

## Latest execution constraint

On 2026-10-29, a fresh Phase 3 launch was attempted through the repository's
QEMU runner with a 2,048 MiB guest. The runner refused before VM boot:

```text
RuntimeError: MemAvailable=3216 MiB; need at least 4096 MiB (2x guest RAM)
```

This is the configured host-side safety guard, not a guest, eBPF, or model
failure. Earlier 1,536 MiB runs also fell below the 3,072 MiB guard while
running, and a 1,024 MiB run was stopped after heavy disk growth. The guard
must remain enabled. A fresh measured corpus and corresponding Phase 6/7
results require a launcher with stable memory headroom and free storage.

After that refusal, the documented tiny-model fallback was tried with a
1,024 MiB guest and 3,072 MiB guest-only swap using the cached tiny-model
image. QEMU launched, but the guest serial log stopped at early kernel boot
(`smpboot: x86: Booting SMP configuration:`); its 11,556-byte log did not
advance for five minutes, QEMU showed no further disk progress, and no result
marker or corpus files were returned. I interrupted the guest wait loop; the
exact runner error was `KeyboardInterrupt` at `scripts/run_phase0_vm.py:584`
while sleeping. This is an incomplete boot attempt, not a model/task failure
or a corpus measurement. Its unique overlay and serial log remain under
ignored `data/vm/` for diagnosis.

Root-cause evidence points to the host KVM path. The launcher host reported
Arch Linux kernel `7.2.11-arch1-1`, QEMU `11.1.2`, and an Intel i7-14650HX.
The kernel journal recorded `kvm_intel: vmread failed` / `vmwrite failed`
VMCS fields, while QEMU logged `KVM: entry failed, hardware error 0x0`.
Separate KVM boot diagnostics reproduced the error with one vCPU and with
`-cpu qemu64`, so neither two-vCPU SMP nor `-cpu host` alone explains it. A
boot-only run using two-vCPU software TCG on the same base image reached the
Ubuntu 24.04.5 login prompt in under two minutes. This supports a host KVM
execution failure; it does not prove the full agent/BPF workload under TCG.

The runner now has an explicit `--qemu-accel tcg` option. KVM remains the
default; the selected acceleration and exact QEMU arguments are recorded in
`data/vm/provenance.json`. TCG is substantially slower and may affect model
task success and timing, so its measurements must remain identified as TCG
runs rather than pooled silently with KVM data. No corpus run has yet been
completed with this option.

A full Phase 3 attempt was then made through the new runner option with the
1,024 MiB tiny-model guest and 3,072 MiB guest swap. TCG booted far enough to
start cloud-init, but the runner stopped QEMU when its live guard observed
`MemAvailable=1918 MiB; need at least 2048 MiB (2x guest RAM)`. The exact
exception was `RuntimeError: host memory headroom fell below 2048 MiB during
guest run`. QEMU was terminated by the runner, no task result bundle was
returned, and no corpus outcomes are inferred from this attempt.

An attempt from the accepted `guest.qcow2` backing image then reached cloud-init
but exited before Phase 3. At that time, the guest reported `virtualization:
qemu` while the runner selected the KVM lock, and the returned
`phase3-corpus.log` was stale data from the base image. No run data is
attributed to that attempt.

The runner now selects `config/environment.tcg.lock.json` for TCG and records
the lock path. This lock carries the same pinned guest facts and packages as
the KVM lock, with the observed virtualization value `qemu`. Startup clears
per-run logs, active run directories, and only the attack/evaluation outputs
being regenerated. The result exporter also skips inactive phase paths before
checking or reading them, preventing stale large files from an immutable base
image from delaying or contaminating handoff.

On 2026-10-29, the runner completed Phase 0 under TCG using the accepted base,
1,024 MiB guest RAM, and 3,072 MiB guest-only swap. The selected TCG lock
matched: Ubuntu 24.04.5, kernel `6.8.0-146-generic`, `virtualization: qemu`,
and cgroup v2. `make check`, all 174 unit tests, the eBPF smoke test, and the
agent-join smoke test passed. The tracer smoke produced 230 events with zero
dropped events. This validates Phase 0 under TCG; Phase 3 corpus execution is
still pending, and TCG timing/task utility must remain separately identified.
The host-side 1,987 MiB headroom stop remains a valid failed Phase 3 attempt.

The next Phase 3 TCG attempt used the accepted base, the same 1,024 MiB guest,
3,072 MiB guest swap, and `config/model.tiny.json`, with a 3,600-second runner
timeout. It ended with the exact error `RuntimeError: guest exceeded 3600
second limit`. QEMU was stopped by the runner; the serial log had no complete
result marker, so no guest logs, corpus rows, or success rate were returned.
The overlay reached about 4.8 GiB. During the run, host memory headroom stayed
above the two-times guard; the runner stopped on elapsed time, not memory.
Because this run predated serial progress forwarding, its quiet serial output
does not reveal how many of the 34 tasks × 3 seeds completed.

After that timeout, the Phase 3 smoke script was updated to stream each flushed
run summary to serial while continuing to save the full runner log in the
guest. Its run-count check now derives the expected total from the manifest's
task and seed counts; the previous hard-coded 90 was stale after the benign
suite grew to 34 tasks (102 runs at three seeds). These changes have unit and
shell-syntax coverage but have not yet been exercised in a guest. A complete
Phase 3 corpus under TCG remains unmeasured.

The `data/vm/` directory is ignored experiment state. Historical images,
logs, and result JSONL there are not source-controlled evidence by themselves;
preserve their config/model locks and inspect the phase notes before use.

## Remaining research work

1. Run the 34-task corpus with the documented pinned model on a host that
   meets the VM memory guard. Record task success, model lock, join quality,
   and per-type variability. Keep unsuccessful tasks in the sample.
2. Rerun Phase 6 with the same refreshed benign corpus and all four strategies.
   Report success and detector rates per strategy at fixed FPR, and describe
   whether each matching benign behavior was actually observed.
3. Obtain useful local-agent success on injection tasks, then rerun Phase 5
   and classify only successful, calibrated cases in Phase 7.
4. Rerun detector and ablation evaluation using a task-held-out split and log
   every false positive cause.
5. Measure blocking utility only if enforcement is implemented; current
   Tripwire records and scores but does not block.
6. Reproduce from a fresh VM using only the README instructions, retain exact
   environment/model locks, and update the paper from measured—not inferred—
   results.

## Change history pointers

The Git log is authoritative for implementation changes and commit boundaries.
This file summarizes research status and should be updated when a new guest
run changes the evidence or when an acceptance criterion is completed.
