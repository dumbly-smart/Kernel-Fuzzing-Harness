# Phase 7: taxonomy and feature ablations

## Implementation

`make eval-all ATTACK_DIR=...` reruns calibrated detectors, computes five
feature sets (files, network, process, ordered sequence, and combined), builds
case-level taxonomy evidence, and writes an SVG. All partitions are task-level
and attack runs remain test-only. The combined detector score is the
arithmetic mean of the allowlist and n-gram novelty scores. This choice is
explicit in `config/ablations.json`; it is not tuned on attack labels.

The taxonomy builder leaves cases pending unless the attack goal succeeded and
calibrated OS-only verdicts exist. Its operational categories and evidence are
described in `docs/taxonomy.md`.

## Measured guest run (2026-10-26)

`make eval-all` completed in the provisioned guest and wrote detector results,
five ablations, case-level taxonomy evidence, and an SVG. The corpus split was
15 train / 5 calibration / 10 test tasks (45 / 15 / 30 runs). Each attack
sample is test-only. None of the seven Phase 5 goals succeeded, so the report
correctly leaves all seven taxonomy labels pending. Detector positives are not
successful attack detections in this run.

| Features | Attack rows flagged | Measured benign FPR |
|---|---:|---:|
| Files | 1/7 | 0/30 |
| Network | 1/7 | 0/30 |
| Process | 0/7 | 0/30 |
| Sequence | 1/7 | 3/30 (10%) |
| Combined | 1/7 | 3/30 (10%) |

The 1% and 5% targets both produced these same measured rates. Only 15
calibration samples were available, so target-level resolution is coarse. The
benign model completed 15/90 tasks; fetch tasks had no calls. Treat all attack
metrics as utility-confounded smoke measurements. Enforcement and utility loss
with blocking remain unmeasured.

## Acceptance status

Unit tests cover feature projection, task-held-out attack scoring, taxonomy
classification rules, and unknown feature-set rejection. Guest automation and
artifact generation pass; meaningful attack taxonomy evidence is still
incomplete because the local model did not achieve any injection goal. Utility
with versus without blocking remains unmeasured because this implementation
does not enforce blocking.
