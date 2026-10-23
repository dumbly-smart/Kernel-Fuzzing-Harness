# Phase 1 Tracer Implementation Plan

> For agentic workers: REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Trace requested file, process, and network syscall metadata for one cgroup v2 tree into ordered JSONL with drop counts.

**Architecture:** CO-RE C programs attach to syscall and scheduler tracepoints, keep syscall entry data in a per-thread map, and emit completed events through one ring buffer. A small libbpf C process attaches and serializes events; Python validates the cgroup path, launches it, and parses JSONL.

**Tech Stack:** C, clang/LLVM 18.1.3, libbpf 1.3.0, bpftool 7.4.0, Python 3.12.3, standard library.

**Spec:** docs/superpowers/specs/2026-10-24-phase1-tracer-design.md; requirements originate in the Phase 1 acceptance criteria in the Tripwire master prompt.

## Global Constraints

- Execute and load BPF only in the disposable Ubuntu 24.04 amd64 KVM guest; kernel >= 5.15 with BTF and cgroup v2.
- Use tracepoints first, a 16 MiB ring buffer, 256-byte path fields and a 1 second polling interval; settings remain explicit and logged.
- Record metadata only for paths and network; never copy socket payloads.
- Filter by cgroup ID and retain ring-buffer drop counts.
- Make small commits and push each verified commit to origin.

## Review Focus

- Invalid user pointers: emit a bounded event with an empty path, never read arbitrary memory; parser tests cover escaped strings and empty/truncated paths.
- Relative openat/rename paths: preserve raw paths and dirfd fields; smoke covers relative and absolute paths.
- IPv4/IPv6 sockaddr: report family, address and host-order port; tests cover both families.
- Failed syscalls: retain negative return codes; smoke includes a missing-file open.
- Ring-buffer pressure: count reservation failures per CPU and report the sum; tests cover drop stats and smoke requires a stats record.

---

### Task 1: Event schema, parser and cgroup CLI

**Files:** config/tripwire.json, tripwire/events.py, tripwire/cli.py, tests/test_events.py, Makefile.

**Interfaces:** Produces parse_event(line: str) -> dict[str, object] and iter_events(lines) -> Iterator[dict[str, object]]. JSONL common fields: type, sequence, monotonic_ns, wall_ns, pid, tgid, ppid, uid, cgroup_id, comm; type is syscall, process_fork, process_exit, or stats. Sequence records ring-consumer order because concurrent monotonic timestamps can race.

- [ ] Write tests for syscall records (including negative return), fork records, drop stats, invalid JSON, missing fields, sequence regressions and timestamp races.
- [ ] Run make test and confirm the new tests fail for missing parser symbols.
- [ ] Implement strict event validation and delivery-sequence ordering in tripwire/events.py.
- [ ] Implement python3 -m tripwire.cli --cgroup PATH --output PATH to validate a directory under /sys/fs/cgroup, use its inode as cgroup ID, and exec build/tripwire-loader.
- [ ] Run make test; expected all tests pass without external Python dependencies.
- [ ] Commit feat: add event schema and Python trace CLI; push.

### Task 2: CO-RE tracepoint program and reproducible build

**Files:** bpf/tripwire.bpf.c, bpf/Makefile, bpf/loader.c; modify root Makefile and .gitignore.

**Interfaces:** BPF rodata target_cgroup_id is set before load. Ring-buffer events use a fixed ABI in bpf/tripwire.bpf.c; loader serializes the fields defined in Task 1. Generated vmlinux.h and skeleton belong under ignored build/.

- [ ] Add build checks for BTF, clang BPF target, libbpf headers/pkg-config and bpftool; run the build target and verify it initially fails because the BPF source is absent.
- [ ] Implement tracepoint pairs for execve/execveat, openat, connect, sendto, write, clone/clone3/fork/vfork, unlink/unlinkat, rename/renameat/renameat2; add sched_process_fork/exit.
- [ ] Read user strings/sockaddrs only with bounded bpf_probe_read_user*; capture no buffer payload. Keep per-thread pending records and count failed ring-buffer reservations in a per-CPU map.
- [ ] Generate vmlinux.h from running kernel BTF; compile with clang 18, -target bpf -O2 -g -D__TARGET_ARCH_x86.
- [ ] Run the BPF object build; expected object and generated skeleton are created without warnings.
- [ ] Commit feat: add CO-RE syscall and process tracepoints; push.

### Task 3: libbpf loader and JSONL stream

**Files:** bpf/loader.c, bpf/event_json.c and bpf/event_json.h; create tests/test_event_json.py and tests/event_json_harness.c.

**Interfaces:** Loader usage: build/tripwire-loader --cgroup-id ID --output FILE --ring-bytes BYTES --poll-ms MS. Loader reads ring records and cumulative per-CPU loss counters, writes UTF-8 JSONL, and emits a final stats record on SIGINT.

- [ ] Write format tests for quote, slash, newline and non-ASCII path bytes plus IPv4 and IPv6 destinations; confirm fail before serializer exists.
- [ ] Implement libbpf open/configure/load/attach, ring-buffer polling, JSON serialization, wall offset, periodic/final lost counts, SIGINT cleanup, and exact attach error reporting.
- [ ] Build loader using pinned guest libbpf and run make test; expected all tests pass.
- [ ] Commit feat: stream libbpf events as JSONL; push.

### Task 4: In-guest smoke test and learning note

**Files:** scripts/smoke_bpf.sh; modify scripts/run_phase0_vm.py, docs/ENVIRONMENT.md and README.md; create docs/notes/phase1.md.

**Interfaces:** Smoke requires root in the disposable guest, creates a temporary cgroup under /sys/fs/cgroup, launches a local TCP sink, runs shell/file/process/network operations under that cgroup and removes the cgroup on exit. VM result artifact includes smoke output and event JSONL summary, with no socket payloads.

- [ ] Write smoke assertions for execve, openat (success/failure), connect/sendto, write metadata, rename/unlink, fork/exit, ordered timestamps and drop stats. Check shell syntax before loader exists.
- [ ] Implement cleanup-safe workload, tracer startup/shutdown and event assertions.
- [ ] Add smoke to VM acceptance command and save its exact output and trace summary.
- [ ] Run make check, make test and sudo scripts/smoke_bpf.sh in powered-off guest. Expected verifier load succeeds, required classes appear in order, and dropped count prints.
- [ ] Write verifier/CO-RE/tracepoint learning note with exact verifier output and limitations. Don't invent verifier problems if none occur.
- [ ] Commit test: add in-guest eBPF smoke test and phase one notes; push.
