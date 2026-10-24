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

## Acceptance status

Unit tests cover feature projection, task-held-out attack scoring, taxonomy
classification rules, and unknown feature-set rejection. The end-to-end
tables and plots require a completed Phase 3 benign corpus and Phase 5
injection run. No detection or utility figures are claimed before those guest
artifacts exist. Utility with versus without blocking remains unmeasured because
this implementation does not enforce blocking.
