# Phase 1: eBPF tracer

## What is implemented

The tracer uses CO-RE C programs attached to syscall entry/exit tracepoints and
scheduler fork/exit tracepoints. It emits bounded metadata records into a BPF
ring buffer. The small libbpf loader writes JSONL, adds a userspace sequence and
wall-clock estimate, and periodically reports cumulative per-CPU ring-buffer
reservation failures. The Python CLI validates a cgroup v2 descendant and
passes its kernel cgroup ID to the loader. A per-thread in-flight map joins
syscall entry arguments to the syscall return value.

Observed calls include `execve`/`execveat`, `openat`, `connect`, `sendto`,
`write`, process creation calls, `unlink`/`unlinkat`, and rename variants. Path
and sockaddr reads are bounded. `write` records descriptor and byte count only;
it does not copy write buffers or socket payloads. IPv4/IPv6 sockaddr metadata
includes address family, address and host-order port.

## Why tracepoints and cgroups

The programs use kernel tracepoints because they expose stable, named syscall
and scheduler events without depending on internal function names or function
entry details. CO-RE relocates accesses to kernel types using BTF, but it does
not make every tracepoint or field universal: the target kernel still needs the
selected tracepoints and compatible BTF. Kprobes remain a possible fallback
only if a required behavior cannot be represented by tracepoints.

The CLI accepts a cgroup below `/sys/fs/cgroup`, resolves it without following
an escaping symlink, and uses the cgroup inode ID as the filter. A PID filter
would miss descendants created after tracing starts and would need continuous
fork/exec bookkeeping. A cgroup includes new descendants when the workload
inherits membership. The smoke test moves its workload shell into the cgroup
before running children. The loader itself remains outside the workload
cgroup.

## Verifier and ABI observations

On the accepted guest, clang compiled the BPF object and libbpf loaded and
attached all programs without a verifier rejection. No verifier constraint
error was observed in this run. Reads from user memory use bounded
`bpf_probe_read_user_str`/`bpf_probe_read_user`; failed reads produce absent or
empty metadata instead of dereferencing the pointer directly. The event uses a
fixed-size ABI and a per-thread pending map to avoid dynamic allocation in BPF.

The first loader build failed exactly because `bpf_map_lookup_elem` lacked its
declaration (`loader.c:102: error: implicit declaration of function
‘bpf_map_lookup_elem’`); adding `<bpf/bpf.h>` fixed it. Live smoke traces then
showed that Linux passes `AT_FDCWD` as `dirfd=-100`, invalid fd arguments can be
negative, and `sched_process_fork` provides a child PID but this event ABI does
not emit a child TGID. The parser now accepts those emitted values and does not
require an unavailable child TGID. Regression tests cover each parser rule.

Ring-buffer reservation failures are accumulated in a per-CPU array map and
reported as a total. This smoke observed zero drops; it does not characterize
loss under sustained load. Userspace sequence numbers express ring-consumer
delivery order. Kernel monotonic timestamps are not used as a strict sort key:
concurrent producers can reserve records in one order and obtain timestamps in
another.

## Acceptance result

See [the guest acceptance record](phase1-guest-acceptance.txt) and the committed
[sample JSONL trace](../../data/samples/phase1-smoke.jsonl). On the pinned Ubuntu
24.04 amd64 guest (kernel `6.8.0-146-generic`, clang 18.1.3, libbpf 1.3.0,
bpftool 7.4.0), `make check` and 27 Python tests passed. The root-only smoke
captured 391 ordered records: 216 syscall records, 5 fork records, 6 exit
records and 164 stats records. It saw `execve`, `openat`, `connect`, `sendto`,
`write`, `renameat2` and `unlinkat`; the failed `openat` returned `-2`. The
final reported drop count was 0 with a 16 MiB ring, 256-byte paths and a 1 s
poll interval. All test network traffic used a temporary listener on guest
loopback. The trace contains only synthetic file contents and no payload.

## Known limits

- Only Ubuntu 24.04 amd64 / kernel `6.8.0-146-generic` was exercised. Ubuntu
  22.04 and other kernels/architectures remain unverified.
- `write` events are metadata for all file descriptors; they are not yet
  classified as socket writes, and payload bytes are never inspected.
- `sendto` and `connect` provide destination metadata when the syscall supplies
  a readable IPv4/IPv6 sockaddr. This does not observe every possible network
  path or identify application-layer intent.
- The per-thread pending map can lose unmatched entry/exit context if its
  capacity is exhausted; only ring-buffer reservation loss is currently
  counted explicitly.
- The smoke confirms operation on this VM; it is not a throughput, overhead,
  or detection-accuracy measurement.

## What to learn

- Linux kernel docs, “BPF Type Format (BTF)”, §1 Introduction and §3 BTF
  Encoding: <https://docs.kernel.org/bpf/btf.html>.
- `bpf-helpers(7)`, `bpf_probe_read_user_str` and `bpf_ringbuf_reserve`; then
  libbpf documentation, “BPF ring buffer”: <https://docs.kernel.org/bpf/ringbuf.html>.
- Linux kernel docs, “Tracepoints”: <https://docs.kernel.org/trace/tracepoints.html>,
  and `tracepoint:syscalls:sys_enter_openat`/`sys_exit_openat` in the guest's
  tracefs event format files under `/sys/kernel/tracing/events/`.
