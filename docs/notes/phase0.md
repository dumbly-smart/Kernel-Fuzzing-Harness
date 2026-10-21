# Phase 0: scaffold and environment

The user supplied the phase design and authorized inline execution. Work is
bounded to directories, reproducible guest setup and environment checks.
Plan: preserve standing instructions; create layout/config/docs; implement
restricted setup and read-only checks; run acceptance and unit checks; record
actual outcomes; commit scaffold and stop. No Phase 1 implementation.

Defaults: Python with a small C loader, a minimal ReAct agent, Ollama. No reply
is required to scaffold; the model and runtime must be pinned before use.

The setup targets one Ubuntu release and architecture to limit reproduction
variables. The dated archive selects package versions; the generated lock pins
all installed package revisions, tool outputs and the actual running kernel.
A base image checksum is also necessary: a snapshot cannot describe packages
already present in an arbitrary image. Setup is idempotent and never replaces an
existing lock to conceal drift. The snapshot endpoint and guest provisioning
have not been exercised from this development environment.

BTF supplies kernel type metadata for later CO-RE relocations. Its existence
alone does not demonstrate verifier acceptance, ring-buffer support, tracepoint
availability or BPF privileges. Phase 0 compiles an empty BPF object to check the
LLVM backend; Phase 1 must load actual programs and retain verifier errors.

No monitor code or third-party implementation was copied. No performance,
detection or utility claim is made. The workspace is an unconfirmed Arch host,
so package installation is excluded. Failure of target-environment acceptance
must remain visible; a unit-test pass cannot substitute for a guest check.

## Acceptance

See `phase0-acceptance.txt` for the actual development-host check output.
Guest setup, repeated setup idempotency, exact environment lock and successful
`make check` on Ubuntu are pending. Stop here until a disposable guest is
available; do not proceed to Phase 1 on the strength of scaffold tests alone.

## What to learn

- `uname(1)`, DESCRIPTION, and `systemd-detect-virt(1)`, DESCRIPTION: a container
  shares its outer kernel; detecting virtualization does not prove ownership.
- Kernel docs, “BPF Type Format (BTF)”, §1 Introduction:
  https://docs.kernel.org/bpf/btf.html — metadata is a prerequisite for CO-RE.
- Ubuntu Snapshot Service, “How to Use Snapshots on Ubuntu”:
  https://snapshot.ubuntu.com/ — distinguish archive pins from image identity.

Local validation: `make test` passed 7 tests, `bash -n scripts/setup_vm.sh`
passed, and `make check` exited 2 through Make (environment checker exit 1).
Missing tools and unsupported OS are recorded verbatim in the acceptance log.
Setup was not executed because package installation on this unconfirmed host is
outside the safety boundary. Review changed snapshot selection to read archive
versions with `apt-cache madison`: policy candidates can otherwise prefer a
newer already-installed version. Guest installation and archive availability
remain unverified.
