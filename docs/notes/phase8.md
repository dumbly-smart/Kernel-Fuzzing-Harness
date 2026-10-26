# Phase 8: reproducible release and writeup

## Release artifacts

- `scripts/reproduce.sh` orchestrates Phase 0, 3, 5, 6, and 7 from a fresh
  launcher host. It provisions QEMU guests without host mounts, checks a
  conservative free-memory headroom rule before each launch, and uses the
  preferred pinned model config unless `MODEL_CONFIG` is set.
- The launcher accepts `GUEST_MEMORY_MIB`, `GUEST_SWAP_MIB`, `GUEST_DISK_GIB`,
  and `GUEST_TIMEOUT_SECONDS`. Its 2x memory rule is a local safety heuristic, not
  a guarantee of model fit; available-memory and VM sizing remain recorded in
  the QEMU provenance. The direct Python VM runner enforces the same rule, so
  bypassing `scripts/reproduce.sh` does not skip the check.
- `LICENSE` uses the MIT License. No AgentSight, Tetragon, or AgentDojo source
  code was copied into Tripwire.
- `docs/paper/WORKSHOP_DRAFT.md` is a workshop draft with preliminary results. Verified
  primary sources are linked, including foundational syscall-sequence and
  mimicry work. One AgentDojo scenario is adapted; full benchmark integration
  and successful injection measurements remain follow-up work.

## Measured implementation status

The accepted guest completed Phase 3 with the explicit tiny profile:
`qwen3:0.6b-q4_K_M`, Ollama 0.40.7, 90 runs, 15 successful tasks (16.7%).
Phase 5 ran seven injections with zero successful goals. Phase 6 reached both
fake-canary goals and both detectors flagged both examples; this was not an
in-envelope evasion because all 18 benign fetch runs had zero calls. Phase 7
produced five ablations, a plot, and seven pending taxonomy rows. See the
phase-specific notes for exact FPR, orphan, and ablation counts.

`scripts/reproduce.sh` now accepts `GUEST_SWAP_MIB` so the measured 1 GiB RAM +
3 GiB guest-swap profile can be requested explicitly. The default 8B profile
and a clean-launcher full reproduction have not been rerun end-to-end in this
turn. Three attempts with the pinned 1.7B profile produced no result bundle;
two hit the live memory guard and the 1 GiB attempt was stopped at 9.5 GiB
free host storage (99% used). The exact readings are in `docs/notes/phase3.md`. `make check` on the development host fails as designed because it is
Arch rather than Ubuntu 24.04 and lacks guest detection, `clang-18`,
`bpftool`, and `dpkg-query`; the disposable guest ran its own check and tests.
The research question therefore remains only partially answered: a capable
model corpus, successful injections, a successful in-envelope evasion, and
blocking utility measurements are still needed.
