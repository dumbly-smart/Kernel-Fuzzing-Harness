#include "vmlinux.h"
#include "event.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 target_cgroup_id;

struct pending_event {
    struct tripwire_event event;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_event);
} inflight SEC(".maps");

/* Per-CPU scratch storage avoids putting the large fixed event on BPF stack. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_event);
} scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16777216);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lost_events SEC(".maps");

static __always_inline int is_target_cgroup(void)
{
    return target_cgroup_id != 0 &&
           bpf_get_current_cgroup_id() == target_cgroup_id;
}

static __always_inline void count_lost_event(void)
{
    __u32 zero = 0;
    __u64 *lost = bpf_map_lookup_elem(&lost_events, &zero);
    if (lost)
        __sync_fetch_and_add(lost, 1);
}

static __always_inline void fill_common(struct tripwire_event *event,
                                        __u32 type)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    event->type = type;
    event->monotonic_ns = bpf_ktime_get_ns();
    event->pid = (__u32)pid_tgid;
    event->tgid = (__u32)(pid_tgid >> 32);
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->uid = (__u32)uid_gid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
}

static __always_inline int read_user_path(char *destination,
                                          const char *source)
{
    long result;

    if (!source) {
        destination[0] = '\0';
        return 0;
    }
    result = bpf_probe_read_user_str(destination, TRIPWIRE_PATH_BYTES, source);
    if (result < 0) {
        destination[0] = '\0';
        return 0;
    }
    return result == TRIPWIRE_PATH_BYTES;
}

static __always_inline void read_user_sockaddr(struct tripwire_event *event,
                                               const void *address,
                                               __u32 length)
{
    __u16 family;
    __u16 network_port;
    long result;

    if (!address || length < sizeof(family))
        return;
    result = bpf_probe_read_user(&family, sizeof(family), address);
    if (result)
        return;

    if (family == 2) { /* AF_INET; sockaddr_in address begins at byte 4. */
        __u32 address_v4;
        if (length < 8)
            return;
        result = bpf_probe_read_user(&network_port, sizeof(network_port),
                                     (const char *)address + 2);
        if (result)
            return;
        result = bpf_probe_read_user(&address_v4, sizeof(address_v4),
                                     (const char *)address + 4);
        if (result)
            return;
        event->family = family;
        event->port = bpf_ntohs(network_port);
        event->address_length = 4;
        __builtin_memcpy(event->address, &address_v4, sizeof(address_v4));
    } else if (family == 10) { /* AF_INET6; address begins at byte 8. */
        if (length < 24)
            return;
        result = bpf_probe_read_user(&network_port, sizeof(network_port),
                                     (const char *)address + 2);
        if (result)
            return;
        result = bpf_probe_read_user(event->address, 16,
                                     (const char *)address + 8);
        if (result)
            return;
        event->family = family;
        event->port = bpf_ntohs(network_port);
        event->address_length = 16;
    } else {
        return;
    }
    event->flags |= TW_HAS_ADDRESS;
}

static __always_inline void begin_syscall(
    const char *name,
    const char *path, const char *path2, __s32 dirfd, __s32 fd,
    __u64 byte_count, const void *address, __u32 address_length)
{
    __u32 zero = 0;
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_event *temporary;

    if (!is_target_cgroup())
        return;
    temporary = bpf_map_lookup_elem(&scratch, &zero);
    if (!temporary) {
        count_lost_event();
        return;
    }
    __builtin_memset(temporary, 0, sizeof(*temporary));
    fill_common(&temporary->event, TW_SYSCALL);
    bpf_probe_read_kernel_str(temporary->event.syscall,
                              sizeof(temporary->event.syscall), name);
    temporary->event.dirfd = dirfd;
    temporary->event.fd = fd;
    temporary->event.byte_count = byte_count;
    if (path) {
        temporary->event.flags |= TW_HAS_PATH;
        if (read_user_path(temporary->event.path, path))
            temporary->event.flags |= TW_PATH_TRUNCATED;
    }
    if (path2) {
        temporary->event.flags |= TW_HAS_PATH2;
        if (read_user_path(temporary->event.path2, path2))
            temporary->event.flags |= TW_PATH2_TRUNCATED;
    }
    read_user_sockaddr(&temporary->event, address, address_length);
    if (bpf_map_update_elem(&inflight, &key, temporary, BPF_ANY) != 0) {
        count_lost_event();
        return;
    }
}

static __always_inline int finish_syscall(struct trace_event_raw_sys_exit *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_event *entry = bpf_map_lookup_elem(&inflight, &key);
    struct tripwire_event *record;

    if (!entry)
        return 0;
    entry->event.return_code = ctx->ret;
    record = bpf_ringbuf_reserve(&events, sizeof(*record), 0);
    if (!record) {
        count_lost_event();
        bpf_map_delete_elem(&inflight, &key);
        return 0;
    }
    __builtin_memcpy(record, &entry->event, sizeof(*record));
    bpf_ringbuf_submit(record, 0);
    bpf_map_delete_elem(&inflight, &key);
    return 0;
}

static __always_inline int emit_process(__u32 type, __u32 child_pid)
{
    __u32 zero = 0;
    struct pending_event *temporary;
    struct tripwire_event *record;

    if (!is_target_cgroup())
        return 0;
    temporary = bpf_map_lookup_elem(&scratch, &zero);
    if (!temporary) {
        count_lost_event();
        return 0;
    }
    __builtin_memset(temporary, 0, sizeof(*temporary));
    fill_common(&temporary->event, type);
    temporary->event.child_pid = child_pid;
    record = bpf_ringbuf_reserve(&events, sizeof(*record), 0);
    if (!record) {
        count_lost_event();
        return 0;
    }
    __builtin_memcpy(record, &temporary->event, sizeof(*record));
    bpf_ringbuf_submit(record, 0);
    return 0;
}

#define ENTER_PROG(function_name, syscall_name, path1, path2, dirfd_value, \
                   fd_value, bytes_value, addr_value, addr_len_value)       \
    SEC("tracepoint/syscalls/sys_enter_" #syscall_name)                     \
    int function_name(struct trace_event_raw_sys_enter *ctx)                 \
    {                                                                        \
        begin_syscall(#syscall_name, path1, path2, dirfd_value,              \
                      fd_value, bytes_value, addr_value, addr_len_value);    \
        return 0;                                                            \
    }

#define EXIT_PROG(function_name, syscall_name)                              \
    SEC("tracepoint/syscalls/sys_exit_" #syscall_name)                      \
    int function_name(struct trace_event_raw_sys_exit *ctx)                 \
    {                                                                        \
        return finish_syscall(ctx);                                          \
    }

ENTER_PROG(enter_execve, execve, (const char *)ctx->args[0], NULL,
           -100, -1, 0, NULL, 0)
EXIT_PROG(exit_execve, execve)
ENTER_PROG(enter_execveat, execveat, (const char *)ctx->args[1], NULL,
           (__s32)ctx->args[0], -1, 0, NULL, 0)
EXIT_PROG(exit_execveat, execveat)
ENTER_PROG(enter_openat, openat, (const char *)ctx->args[1], NULL,
           (__s32)ctx->args[0], -1, 0, NULL, 0)
EXIT_PROG(exit_openat, openat)
ENTER_PROG(enter_connect, connect, NULL, NULL, -1,
           (__s32)ctx->args[0], 0, (const void *)ctx->args[1],
           (__u32)ctx->args[2])
EXIT_PROG(exit_connect, connect)
ENTER_PROG(enter_sendto, sendto, NULL, NULL, -1,
           (__s32)ctx->args[0], ctx->args[2], (const void *)ctx->args[4],
           (__u32)ctx->args[5])
EXIT_PROG(exit_sendto, sendto)
ENTER_PROG(enter_write, write, NULL, NULL, -1,
           (__s32)ctx->args[0], ctx->args[2], NULL, 0)
EXIT_PROG(exit_write, write)
ENTER_PROG(enter_clone, clone, NULL, NULL, -1, -1, 0, NULL, 0)
EXIT_PROG(exit_clone, clone)
ENTER_PROG(enter_clone3, clone3, NULL, NULL, -1, -1, 0, NULL, 0)
EXIT_PROG(exit_clone3, clone3)
ENTER_PROG(enter_fork, fork, NULL, NULL, -1, -1, 0, NULL, 0)
EXIT_PROG(exit_fork, fork)
ENTER_PROG(enter_vfork, vfork, NULL, NULL, -1, -1, 0, NULL, 0)
EXIT_PROG(exit_vfork, vfork)
ENTER_PROG(enter_unlink, unlink, (const char *)ctx->args[0], NULL,
           -100, -1, 0, NULL, 0)
EXIT_PROG(exit_unlink, unlink)
ENTER_PROG(enter_unlinkat, unlinkat, (const char *)ctx->args[1], NULL,
           (__s32)ctx->args[0], -1, 0, NULL, 0)
EXIT_PROG(exit_unlinkat, unlinkat)
ENTER_PROG(enter_rename, rename, (const char *)ctx->args[0],
           (const char *)ctx->args[1], -100, -1, 0, NULL, 0)
EXIT_PROG(exit_rename, rename)
ENTER_PROG(enter_renameat, renameat, (const char *)ctx->args[1],
           (const char *)ctx->args[3], (__s32)ctx->args[0], -1, 0, NULL, 0)
EXIT_PROG(exit_renameat, renameat)
ENTER_PROG(enter_renameat2, renameat2, (const char *)ctx->args[1],
           (const char *)ctx->args[3], (__s32)ctx->args[0], -1, 0, NULL, 0)
EXIT_PROG(exit_renameat2, renameat2)

SEC("tracepoint/sched/sched_process_fork")
int process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    return emit_process(TW_PROCESS_FORK, ctx->child_pid);
}

SEC("tracepoint/sched/sched_process_exit")
int process_exit(void *ctx)
{
    (void)ctx;
    return emit_process(TW_PROCESS_EXIT, 0);
}
