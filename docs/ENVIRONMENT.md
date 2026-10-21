# Environment and pins

## Target

- OS: Ubuntu 24.04 LTS; architecture: amd64.
- Ubuntu archive snapshot: **20261001T000000Z** (UTC).
- Toolchain family: clang/LLVM 18; exact Debian revisions and transitive packages
  are resolved from that snapshot, installed with `package=version`, and recorded
  in `config/environment.lock.json` by setup. The lock is compared on every check.
- Kernel: generic Ubuntu kernel resolved from the snapshot; minimum 5.15,
  readable `/sys/kernel/btf/vmlinux`, cgroup v2. Exact release recorded in lock
  after reboot. No floating kernel is accepted against an existing lock.
- libbpf/libelf/zlib, bpftool, Make, Python: same snapshot and exact lock.
- Python dependencies: standard library only. No pip dependencies.
- Intended userspace: Python plus small C/libbpf loader; agent: minimal ReAct;
  runtime: Ollama. These are defaults pending user preference. Runtime/model are
  **not installed or pinned yet**; choose exact runtime version, model digest,
  quantization, seed and sampling settings before agent work. Paid APIs disabled.

## Reproduction identities still required

TODO(verify): guest ISO filename and SHA256, hypervisor version, generated exact
package/tool/kernel lock, successful guest acceptance log. Until these are
recorded, Phase 0 environment acceptance is **incomplete**. No exact Ubuntu
versions or successful VM results have been inferred from this development host.
The archive date pins package availability; it does not pin a VM image.

Snapshot sources are temporary and isolated from guest sources and indexes;
signature verification stays enabled. Check-Valid-Until is disabled only for
historical snapshot metadata. Setup does not rewrite the guest's global APT
configuration. Existing automatic updates can cause lock drift: snapshot the
accepted VM and restore it for experiments. Review upgrades as new environments.

## Observed development environment (not the target guest)

2026-10-21: Arch Linux; virtualization probe returned `none` (exit 1).
Kernel `7.2.11-arch1-1`; BTF file readable; clang `23.1.3`;
libbpf via pkg-config `1.7.0`; Python `3.14.8`; Make `4.4.1`.
`bpftool` and `clang-18` were not found. No package installation or BPF loading
was attempted here. Read-only environment checks can run here and must fail.

## Primary references

- [Ubuntu Snapshot Service: How to Use Snapshots](https://snapshot.ubuntu.com/)
- [Kernel BTF: 1. Introduction](https://docs.kernel.org/bpf/btf.html)
- [libbpf: Building libbpf](https://docs.kernel.org/bpf/libbpf/libbpf_build.html)
