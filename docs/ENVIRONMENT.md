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
- libbpf/libelf/zlib, bpftool, Make, Python, and `curl` (used by the local
  naive mimicry baseline): same snapshot and exact lock. The accepted lock has
  curl `8.5.0-2ubuntu10.15`.
- Python dependencies: standard library plus Ubuntu's pinned `python3-yaml`.
- Intended userspace: Python plus small C/libbpf loader; agent: minimal ReAct;
  local runtime: Ollama 0.40.7, installed from a SHA256-pinned official
  `ollama-linux-amd64.tar.zst` release archive. Paid APIs are disabled.
- Preferred Phase 3 model profile: `qwen3:8b-q4_K_M`, quantized Q4_K_M, with
  2048 context tokens, temperature 0, 512 prediction tokens and at most 8 tool
  turns. The exact manifest digest and layer digests are generated in
  `config/model.lock.json` inside the guest and returned with corpus artifacts.
- Constrained-host profile: `config/model.low-memory.json` selects the official
  `qwen3:1.7b-q4_K_M` tag with the same generation settings. It is an explicit
  utility confound, not interchangeable with the preferred 8B model. Its
  manifest lock is kept separately as `config/model.low-memory.lock.json`.
- Last-resort profile: `config/model.tiny.json` selects
  `qwen3:0.6b-q4_K_M` for hosts that cannot safely allocate the larger guests.
  Treat it as a severe utility confound. The official catalog lists a 523 MB
  model artifact; this is storage size, not a measured RAM requirement. Its
  exact manifest lock is `config/model.tiny.lock.json`.
  Model sizes and license are documented by the [official Qwen3 Ollama
  library entry](https://ollama.com/library/qwen3%3A1.7b-q4_K_M); no benchmark
  performance is inferred from the catalog page.
- Research parameters for detector features, task-level split, n-gram order and
  FPR targets live in `config/detectors.json`.
- The local fixture sink binds to guest loopback port 18481, recorded in
  `config/lab.json`. Keeping the same port across corpus and attack runs avoids
  treating a random ephemeral port as a behavioral deviation.

## QEMU acceleration locks

KVM remains the default runner backend and uses
`config/environment.lock.json`. The explicit `--qemu-accel tcg` mode uses
`config/environment.tcg.lock.json`, which pins the same guest configuration,
kernel, and package set but records the observed `systemd-detect-virt` value
`qemu`. The runner selects the matching lock and records its path in VM
provenance. The guest check still compares every field; it does not ignore
environment drift. TCG is much slower and may change model task utility and
timing, so keep its measurements separate from KVM results. Phase 0 acceptance
also passed under TCG on 2026-10-29 using the accepted base image, 1,024 MiB
guest RAM, and 3,072 MiB guest-only swap. The selected lock matched
`virtualization: qemu`; `make check`, 174 unit tests, the eBPF smoke test, and
agent-join smoke test passed. The tracer smoke reported 230 events and zero
drops. A Phase 3 corpus run under TCG remains pending.
The first full 34-task × 3-seed TCG attempt exceeded its 3,600-second runner
limit before the result bundle was returned; it is not a corpus measurement.
A later attempt streamed its first run summary, which reported the pinned
Ollama request timeout after about 28 minutes of QEMU runtime. It was
interrupted before the full suite and returned no corpus bundle. The runner
now also streams model installation output and stage markers; that addition
was exercised in a guest by the bounded diagnostic described below. Details
are in `progress.md`.

The 2026-10-29 one-task follow-up used
`config/model.tcg-diagnostic.json`, locked separately in
`config/model.tcg-diagnostic.lock.json`: Ollama 0.40.7,
`qwen3:0.6b-q4_K_M`, context 1,024, prediction limit 128, request timeout
900 seconds, keep-alive 300 seconds, and at most two agent turns. The config
and lock were seeded through NoCloud; the guest verified its cached model,
entered the corpus stage, and returned a complete artifact bundle. Its only
task still timed out and the manifest recorded 0/1 success. The bundle's 399
events and zero tool calls make its all-orphan event count unsuitable for join
evaluation. Treat this as VM handoff/export success and model utility failure,
not a corpus measurement. Two higher-memory launches were blocked by the live
guard at 4,056/4,096 MiB available for a 2,048 MiB guest and 3,022/3,072 MiB
for a 1,536 MiB guest in earlier attempts; neither booted. Two later launches
did boot after temporary headroom recovery, but the runtime guard stopped the
2,048 MiB guest at 4,019/4,096 MiB and the 1,536 MiB guest at 3,019/3,072 MiB.
Neither produced the result metadata marker or a complete bundle. More details
are in `progress.md`.

The separate `config/model.tcg-lowcontext.json` profile and paired lock retain
the same model/runtime pin while lowering the context limit from 1,024 to 512
tokens. Its 1 GiB guest verified the cached model and reached the corpus stage,
but the host guard stopped it at 2,020/2,048 MiB available. It returned no task
row or complete bundle; this does not show whether lower context improves
inference. Keep that profile separate from research corpus settings.

## Accepted guest — 2026-10-22

Phase 0 acceptance passed on a disposable QEMU/KVM guest:

| Component | Observed version |
| --- | --- |
| Cloud image | Ubuntu 24.04 amd64, release-20260926 |
| Kernel | 6.8.0-146-generic |
| Clang | 18.1.3 (1ubuntu1) |
| libbpf (pkg-config) | 1.3.0 |
| bpftool | 7.4.0, with its own libbpf 1.4 |
| Python | 3.12.3 |
| Make | 4.3 |
| QEMU on the launcher host | 11.1.2 |

The cloud image replaces the manual ISO route for this accepted environment.
Its URL, signed-manifest fingerprint, SHA256, launch arguments and tested source
commit are in [VM provenance](notes/phase0-vm-provenance.json).
Exact package revisions (including transitive dependencies) and tool output are
in [the environment lock](../config/environment.lock.json).
The host launcher uses QEMU 11.1.2 and generates its NoCloud seed ISO with the
Python standard library; no host ISO utility or package installation is needed.
The regression boot from a guest with persisted UFW lockdown is recorded in
[the bootstrap note](notes/phase0-vm-bootstrap.md).
The difference between pkg-config's libbpf and bpftool's reported libbpf reflects
separate build dependencies; later C loaders use the development package.

Setup installed the generic kernel, requested a reboot from 6.8.0-142-generic,
then succeeded on 6.8.0-146-generic. A repeated setup succeeded against the same
lock. `make check` and all 10 tests passed as user `ubuntu`; see
[the guest acceptance log](notes/phase0-guest-acceptance.txt).
BTF was readable, cgroup v2 was present, and the clang BPF backend compiled an
empty object. That was the Phase 0 check; the tracer was loaded in the separate
Phase 1 acceptance run below. The former host failure log remains as historical
evidence.

## Phase 1 tracer acceptance — 2026-10-24

The accepted baseline disk was reused read-only behind a fresh disposable
overlay. Setup idempotence, `make check`, 43 Python tests, BPF compilation,
libbpf loading/tracepoint attachment and the root-only smoke all passed on the
same pinned environment above. The final cadence-checked smoke emitted 229 records with zero
reported ring-buffer drops. Configuration was 16 MiB ring buffer, 256-byte path
fields and 1000 ms stats polling. Summary and exact guest record:
[phase1-guest-acceptance.txt](notes/phase1-guest-acceptance.txt). The sample
JSONL is in `data/samples/phase1-smoke.jsonl`; raw overlays and run artifacts
remain ignored under `data/vm/`.

## Phase 2 correlation acceptance — 2026-10-24

The same disposable baseline and tool pins passed `make check`, 43 Python tests,
the BPF smoke and the ten-task tool-call join smoke. All 11 logged tool calls
were joined to one or more events. The join report counted 428 assigned, 1,781
orphaned (80.62%) and zero ambiguous events out of 2,209 records. Most orphans
were interpreter startup syscalls outside call windows; the cause breakdown and
limits are recorded in [Phase 2 notes](notes/phase2.md). `late_event_grace_ms`
is 250 in `config/tripwire.json`; collector poll/stats cadence is 1,000 ms.

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
