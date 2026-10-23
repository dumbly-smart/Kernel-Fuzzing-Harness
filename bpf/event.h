#ifndef TRIPWIRE_EVENT_H
#define TRIPWIRE_EVENT_H

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

#define TRIPWIRE_PATH_BYTES 256
#define TRIPWIRE_COMM_BYTES 16
#define TRIPWIRE_SYSCALL_BYTES 16

enum tripwire_event_type {
    TW_SYSCALL = 1,
    TW_PROCESS_FORK = 2,
    TW_PROCESS_EXIT = 3,
    TW_STATS = 4,
};

enum tripwire_event_flags {
    TW_HAS_PATH = 1U << 0,
    TW_HAS_PATH2 = 1U << 1,
    TW_HAS_ADDRESS = 1U << 2,
    TW_PATH_TRUNCATED = 1U << 3,
    TW_PATH2_TRUNCATED = 1U << 4,
};

/* Fixed-size ABI keeps ring-buffer records simple to verify and consume. */
struct tripwire_event {
    __u32 type;
    __u32 flags;
    __u64 monotonic_ns;
    __u64 cgroup_id;
    __u64 byte_count;
    __u64 ring_buffer_bytes;
    __u64 poll_interval_ms;
    __s64 return_code;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 child_pid;
    __s32 dirfd;
    __s32 fd;
    __u32 family;
    __u32 port;
    __u32 address_length;
    __u32 path_bytes;
    __u8 address[16];
    char syscall[TRIPWIRE_SYSCALL_BYTES];
    char comm[TRIPWIRE_COMM_BYTES];
    char path[TRIPWIRE_PATH_BYTES];
    char path2[TRIPWIRE_PATH_BYTES];
};

#endif
