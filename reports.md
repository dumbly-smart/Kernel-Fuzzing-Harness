# Reports and experiment artifacts

This page is an index and interpretation guide for Tripwire outputs. Generated
guest artifacts under `data/vm/` are ignored by Git and are not automatically
part of a checkout. Preserve the exact configs, lock files, run manifests,
logs, and source revision with any artifact you analyze.

## Record types

| File | Meaning |
|---|---|
| `runs.jsonl` | One attempted task/attack per JSON line, including success/error and labels. |
| `calls.jsonl` | One agent tool call per line, with call ID, arguments, PIDs, cgroup, and monotonic time window. |
| `events.jsonl` | Parsed eBPF event stream, including `stats` records for lost-event counters. |
| `joined.jsonl` | Tool-call records annotated with assigned behavioral events. |
| `join-report.json` | Assigned, orphan, ambiguous, stats, dropped-event and grace-window counts. |
| `manifest.json` | Run metadata, effective research configs, task/model profile, and measurement kind. |
| `detector-eval/results.json` | Task split, thresholds/config, per-detector metrics and corpus counts. |
| `detector-eval/scores.jsonl` | Per-sample raw detector scores and explanations. |
| `detector-eval/attack-verdicts.jsonl` | Thresholded verdict per attack, detector, and target FPR. |
| `detector-eval/false-positives.jsonl` | Benign test samples flagged, with causes for inspection. |
| `taxonomy-results.json` | Case goal, expected and observed OS evidence, verdicts, and operational class or `pending`. |
| `ablation-eval/results.json` | Feature-set metrics for files, network, process, sequence, combined. |
| `ablation-eval/false-positives.jsonl` | False-positive cases for each ablation. |
| `ablation-eval/attack-verdicts.jsonl` | Attack scores/verdicts for ablations. |
| `ablation-eval/ablation-tpr.svg` | Static plot generated from ablation results. |
| `mimicry-summary.json` | Per-strategy goal outcome and per-detector verdict summary. |

The exact artifact names returned from QEMU are listed in
`scripts/run_phase0_vm.py`. Run directories are deliberately unique; existing
results are preserved instead of overwritten.

## How to read the metrics

- **Goal success** is determined by a task success predicate or a matching
  synthetic canary receipt at the loopback sink. A tool call or suspicious OS
  event alone does not prove the intended attack succeeded.
- **TPR** is the fraction of attack rows above a detector threshold. If attack
  goals failed, this is not a successful-attack detection rate.
- **Target FPR** is the requested calibration quantile, here 1% or 5%.
  **Measured FPR** is the observed fraction of held-out benign rows flagged;
  with a small calibration/test set it can differ substantially from target.
- **Thresholds** are calibrated using benign calibration tasks. Runs of one
  task stay in a single partition. Attack rows are test-only.
- **Orphan-event rate** is behavioral events not assigned to a tool call divided
  by behavioral event count. `stats` snapshots are reported separately.
- **Stable/noisy features** count feature presence across task attempts; they
  are corpus summaries, not universal allowlists.
- **OS-visible / partially visible / OS-invisible** are operational labels for
  successful goals and calibrated OS-only detector outcomes under the current
  model, features, kernel, and thresholds. Unsuccessful or unscored cases are
  `pending`.
- **Ablations** are comparisons of configured feature subsets. They do not
  establish causality or generalization beyond the small measured corpus.

See `docs/notes/phase4.md`, `phase5.md`, `phase6.md`, `phase7.md`, and
`docs/taxonomy.md` for method details and caveats.

## Currently documented historical results

These values come from the saved Phase 3–7 notes and guest artifacts dated
2026-10-26. They are not results for the four benign task definitions added
after the measured 30-task corpus.

| Evidence | Historical result | Interpretation |
|---|---:|---|
| Benign corpus | 30 tasks × 3 seeds = 90 runs; 15 goals succeeded | Qwen3 0.6B Q4_K_M; 16.7% utility success is a severe confound. |
| Behavioral event joining | 174/1,218 assigned; 1,044 orphan (85.71%); 0 ambiguous; 0 dropped | Tool-to-syscall correspondence is incomplete. 2,675 `stats` rows excluded from denominator. |
| Injection suite | 7 cases; 0 goals succeeded | No successful injection evidence; taxonomy stays pending. |
| Mimicry campaign | 2/2 local canary goals reached | Only the earlier naive and one-call adaptive profiles were measured. |
| Mimicry allowlist | 2/2 flagged at 1% and 5%; 0/30 measured benign false positives | Two deterministic probe rows, not an attack population estimate. |
| Mimicry n-gram | 2/2 flagged at 1% and 5%; 3/30 measured benign false positives (10%) | All 18 benign fetch attempts had zero tool calls, so adaptive fetch was not meaningfully in-envelope. |
| Taxonomy | 7/7 cases pending | No injection goal succeeded. Detector positives on failed attempts are not attack TPR. |
| Ablations | Files 1/7, network 1/7, process 0/7, sequence 1/7, combined 1/7 flagged | Attacks failed, so these are not successful-attack detection rates. Measured benign FPR was 0/30 for files/network/process, 3/30 (10%) sequence/combined. |

The saved `data/vm/phase6-summary.json` predates the padding and workspace-file
scope strategies and reports two records. Although current code defines four
profiles and the benign task directory now has 34 definitions, no new corpus
or mimicry run has established results for those additions. The current
development launcher attempt was refused before boot because `MemAvailable`
was 3,216 MiB while the 2 GiB VM policy requires 4,096 MiB; see
`progress.md`. A subsequent 1 GiB tiny-profile guest stopped making serial and
disk progress during early kernel boot and was interrupted after five minutes.
The host journal recorded KVM VMCS read/write errors and QEMU logged
`KVM: entry failed, hardware error 0x0`; this repeated with one vCPU and a
generic `qemu64` CPU model. The same base image reached the Ubuntu login prompt
under a two-vCPU TCG boot-only diagnostic. That establishes a host KVM-path
failure for these attempts, not a guest-image failure. TCG has not been used
for corpus measurement. Neither attempt is an experiment result.

## Reproduce or refresh reports

Use the commands in `README.md` and `scripts/reproduce.sh` from a host with
adequate memory headroom and a working QEMU/KVM setup. Phase 3 must be refreshed
after changing benign task definitions; phases 5–7 must then use that same
corpus and the preserved model/config locks. For existing generated data:

```sh
make eval-detectors CORPUS_DIR=data/phase3-corpus ATTACK_DIR=data/injection-corpus
ATTACK_DIR=data/injection-corpus make eval-all
```

The actual guest paths and the resolved corpus can differ; check each run's
manifest rather than assuming a default path. Do not mix artifacts from
different corpus IDs or model profiles in one table.
