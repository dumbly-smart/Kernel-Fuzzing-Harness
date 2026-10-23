#include "event.h"
#include "event_json.h"

#include <stdio.h>
#include <string.h>

static int write_one(struct tripwire_event *event, unsigned long long sequence,
                     unsigned long long wall, unsigned long long dropped)
{
    char output[8192];
    size_t length = event_json_write(output, sizeof(output), event, sequence,
                                     wall, dropped);
    if (length == 0)
        return 1;
    puts(output);
    return 0;
}

int main(void)
{
    struct tripwire_event event = {0};
    event.type = TW_SYSCALL;
    event.monotonic_ns = 101;
    event.pid = 42;
    event.tgid = 41;
    event.ppid = 7;
    event.uid = 1000;
    event.cgroup_id = 1234;
    event.return_code = -2;
    memcpy(event.comm, "agent", 6);
    memcpy(event.syscall, "openat", 7);
    event.flags = TW_HAS_PATH;
    memcpy(event.path, "a\"b\\c\n", sizeof("a\"b\\c\n"));
    event.flags |= TW_HAS_PATH2;
    memcpy(event.path2, "caf\xc3\xa9", sizeof("caf\xc3\xa9"));
    if (write_one(&event, 1, 201, 0))
        return 1;

    memset(&event, 0, sizeof(event));
    event.type = TW_SYSCALL;
    event.monotonic_ns = 102;
    event.pid = 42;
    event.tgid = 41;
    event.ppid = 7;
    event.cgroup_id = 1234;
    event.flags = TW_HAS_ADDRESS;
    event.family = 2;
    event.port = 8080;
    event.address_length = 4;
    event.address[0] = 127;
    event.address[3] = 1;
    memcpy(event.syscall, "connect", 8);
    if (write_one(&event, 2, 202, 0))
        return 1;

    memset(&event, 0, sizeof(event));
    event.type = TW_SYSCALL;
    event.monotonic_ns = 103;
    event.pid = 42;
    event.tgid = 41;
    event.ppid = 7;
    event.cgroup_id = 1234;
    event.flags = TW_HAS_ADDRESS;
    event.family = 10;
    event.port = 443;
    event.address_length = 16;
    event.address[15] = 1;
    memcpy(event.syscall, "connect", 8);
    if (write_one(&event, 3, 203, 0))
        return 1;

    memset(&event, 0, sizeof(event));
    event.type = TW_STATS;
    event.monotonic_ns = 104;
    event.pid = 1;
    event.tgid = 1;
    event.cgroup_id = 1234;
    event.ring_buffer_bytes = 16777216;
    event.path_bytes = TRIPWIRE_PATH_BYTES;
    event.poll_interval_ms = 1000;
    if (write_one(&event, 4, 204, 9))
        return 1;

    memset(&event, 0, sizeof(event));
    event.type = TW_SYSCALL;
    event.monotonic_ns = 105;
    event.pid = 42;
    event.tgid = 41;
    event.cgroup_id = 1234;
    event.flags = TW_HAS_PATH;
    event.path[0] = (char)0xff;
    memcpy(event.syscall, "openat", 7);
    if (write_one(&event, 5, 205, 9))
        return 1;
    return 0;
}
