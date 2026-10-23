# Phase 1: eBPF tracer design

## Intent and success

Build the first inspectable OS event source for the Tripwire study. It records syscalls, selected file operations, process creation and exit, and network metadata for one cgroup v2 subtree. The accepted Ubuntu guest must compile and load the CO-RE program, run a scripted shell workload in the monitored cgroup, emit parseable ordered JSONL, and report ring-buffer losses.

## Constraints

Build and load BPF only in the powered-off disposable Ubuntu 24.04 KVM guest described in docs/ENVIRONMENT.md. Use C/libbpf for BPF and its small native loader, with a Python CLI wrapper and standard-library event parser. No Python packages, paid APIs, real credentials, packet payloads, or external sink. The local smoke sink is created and stopped by the smoke script. Do not copy code from other tracers.

## Approaches

- Tracepoints and a ring buffer: stable syscall/process event boundaries, explicit return codes from syscall exits, and one ordered event channel. Chosen for this first tracer.
- Kprobes: lower-level visibility, with extra kernel implementation and signature risk for the first tracer.
- Perf events: available on older kernels, but per-CPU buffers make loss accounting and one ordered stream more involved.

## Design

Each syscall enter tracepoint stores bounded metadata in a per-thread in-flight map. Its matching exit emits that metadata and the return value. Tracepoints cover execve/execveat, openat, connect, sendto, write, clone/clone3/fork/vfork, unlink/unlinkat, and rename/renameat/renameat2. Scheduler fork and exit tracepoints record process-tree events. Paths are user strings captured at syscall entry; relative paths remain relative to their supplied dirfd. The write event reports fd and byte count only; it does not copy buffer contents. A sendto/connect event reports destination sockaddr only. Paths and addresses are bounded.

At event time, BPF checks bpf_get_current_cgroup_id() against a loader-provided ID. Children inherit cgroup membership, so a cgroup follows the agent process tree across fork/exec; PID filtering would need updates for each child. The cgroup is a tracing filter, not a sandbox. A per-CPU counter records ring-buffer reservation failures. Events contain monotonic time, a wall-time estimate derived from a userspace clock offset, pid/tgid/ppid/uid, cgroup ID, comm, event class, syscall, return code, and relevant path/address metadata.

The C/libbpf loader attaches declared syscall/scheduler tracepoint programs, consumes the ring buffer, writes JSONL, emits aggregate drop counters on a timer, and detaches cleanly on SIGINT. Python resolves and validates the cgroup path, starts the native loader with the cgroup ID, and provides a strict JSONL parser. An in-guest smoke script loads the program, places a shell workload in a fresh cgroup, exercises file/process/local-network operations, checks event ordering and required classes, and reports dropped events.

## Implementation decisions

Use a 16 MiB ring buffer, 256-byte path fields and a 1 second poll/stat interval as initial explicit settings in config/tripwire.json. Log them in run metadata because they affect observability. Wall-time mapping may be inaccurate if the clock is stepped while tracing. openat path capture does not resolve dirfd/cwd into an absolute pathname. write cannot portably prove an fd is a socket, so it records metadata for write calls on any fd; sendto separately reports a destination. CO-RE does not promise tracepoints exist on every kernel; attach failures must name the exact tracepoint.
