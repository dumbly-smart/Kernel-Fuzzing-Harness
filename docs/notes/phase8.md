# Phase 8: reproducible release and writeup

## Release artifacts

- `scripts/reproduce.sh` orchestrates Phase 0, 3, 5, 6, and 7 from a fresh
  launcher host. It provisions QEMU guests without host mounts, checks a
  conservative free-memory headroom rule before each launch, and uses the
  preferred pinned model config unless `MODEL_CONFIG` is set.
- The launcher accepts `GUEST_MEMORY_MIB`, `GUEST_DISK_GIB`, and
  `GUEST_TIMEOUT_SECONDS`. Its 2x memory rule is a local safety heuristic, not
  a guarantee of model fit; available-memory and VM sizing remain recorded in
  the QEMU provenance. The direct Python VM runner enforces the same rule, so
  bypassing `scripts/reproduce.sh` does not skip the check.
- `LICENSE` uses the MIT License. No AgentSight, Tetragon, or AgentDojo source
  code was copied into Tripwire.
- `docs/paper/WORKSHOP_DRAFT.md` is the workshop paper skeleton. Verified
  primary sources are linked, including foundational syscall-sequence and
  mimicry work. AgentDojo integration feasibility and all missing measurements
  remain marked for follow-up rather than reported as completed.

## Acceptance status

Static suite, VM orchestration, detector, attacker, ablation, taxonomy, and
paper artifacts are implemented. Local verification passes. A fresh-VM
end-to-end reproduction and the main results table remain unaccepted because
the current host could not complete the Phase 3 model guest without risking
another host-wide OOM. The script intentionally aborts when its headroom check
fails. No outcome is synthesized from unit tests or incomplete VM boots.
