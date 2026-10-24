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

## Initial host acceptance attempt (superseded by guest acceptance below)

See `phase0-acceptance.txt` for the actual development-host check output.
At this initial attempt, guest setup, repeated setup idempotency, exact
environment lock and successful `make check` on Ubuntu were pending. This
was not sufficient to proceed to Phase 1.

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


## Accepted guest run — 2026-10-22

An isolated QEMU/KVM guest completed Phase 0 with exit 0. The signed Ubuntu
release-20260926 image booted 6.8.0-142-generic initially; setup reported exactly:

```text
ERROR: running 6.8.0-142-generic; installed 6.8.0-146-generic. Reboot the VM into that kernel, then rerun setup. Containers must use a matching guest VM kernel.
```

Diagnosis: installing the pinned kernel does not replace the running kernel.
The VM rebooted into 6.8.0-146-generic, completed setup, repeated setup
successfully, then passed `make check` and all 10 tests as the unprivileged
Ubuntu user. See `phase0-guest-acceptance.txt` and `phase0-vm-provenance.json`.
The exact version lock is committed in `config/environment.lock.json`.

The first image download timed out after 240 seconds (curl exit 28) at
554696704 of 625612288 bytes. A range-resumed download completed, and signature
and full-image SHA256 checks passed before boot. The initial launch used
`nocloud-net`; the current runner uses a local NoCloud seed ISO. See
[the bootstrap regression note](phase0-vm-bootstrap.md) for why network-fetched
cloud-init data failed on a guest with persisted egress lockdown and the
successful locked-base verification.

Known limits: this validates one Ubuntu 24.04 amd64 guest, not Ubuntu 22.04 or
other architectures; no actual BPF program was loaded. Runtime/model pinning
remains pending before agent work. No attack or detector code was started.
The accepted VM powered off; its disk and raw logs remain gitignored under
`data/vm/`. Stop at this phase boundary and wait for user direction.
