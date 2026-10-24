# Phase 4: benign OS-behavior baselines

## Implemented

- The feature extractor maps trace syscalls to coarse classes and emits ordered
  `(tool, syscall-class)` tokens. Workspace paths lose only the unique run
  directory so the same task file compares equal across seeds. Paths outside
  the workspace retain their full absolute identity.
- The allowlist baseline learns paths, executable names, hosts, and syscall
  names by task type. A sample score is the fraction of unique observed values
  absent from its task-type profile; the score includes an explicit per-field
  cause list.
- The sequence baseline stores observed trigram tuples for each task type and
  scores the fraction of ordered n-grams absent from training.
- Repeated seeds for one task stay in a single partition. Per task type, the
  fixed seed shuffles distinct task IDs and assigns separate train,
  calibration, and test sets. Detector profiles use training tasks; thresholds
  use benign calibration runs; reported measurements use held-out test runs.
- `make eval-detectors` writes scores, metrics, split membership, and a cause
  row for every false positive. TPR remains null for a benign-only corpus and
  becomes defined when Phase 5 attack labels are added.

## Research parameters and limits

`config/detectors.json` sets the feature list, trigram order, split seed,
calibration/test fractions, and requested 1%/5% false-positive rates. Threshold
comparisons are strictly `score > cutoff`; calibration caps false alarms using
an order statistic, so tied scores are conservative. With only 30 distinct
tasks and three repeated seeds, the calibration sample is too small to resolve
1% or 5% rates finely. Metrics include actual held-out false-positive rate and
sample counts. Add more distinct tasks before drawing claims at those rates.

The allowlist is intentionally simple: one novel syscall, path, binary, or host
can affect a score, and path identity can be noisy. N-gram novelty ignores
frequency and semantic meaning. Neither baseline currently enforces or blocks
agent actions.

## Acceptance

Pure-Python unit tests cover syscall classes, workspace path normalization,
task-level splitting, baseline novelty scores, thresholds, confusion counts,
and false-positive cause output. End-to-end `make eval-detectors` requires a
completed Phase 3 corpus in the disposable guest; it has not yet run against
that corpus.
