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
