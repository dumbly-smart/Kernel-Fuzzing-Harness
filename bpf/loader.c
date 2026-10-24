#define _GNU_SOURCE

#include "event_json.h"
#include "tripwire.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MIN_RING_BYTES 4096U
#define MAX_TRACEPOINTS 64

static volatile sig_atomic_t stopping;
static FILE *event_output;
static uint64_t sequence_number;
static uint64_t wall_offset_ns;
static int output_error;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static uint64_t clock_ns(clockid_t clock_id)
{
    struct timespec now;

    if (clock_gettime(clock_id, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static int parse_u64(const char *text, uint64_t *result)
{
    char *end = NULL;
    unsigned long long value;

    if (text[0] == '-')
        return -1;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno || end == text || *end != '\0')
        return -1;
    *result = (uint64_t)value;
    return 0;
}

static int write_record(const struct tripwire_event *event,
                        uint64_t dropped_events)
{
    char json[8192];
    size_t length;
    uint64_t wall_ns = event->monotonic_ns + wall_offset_ns;

    length = event_json_write(json, sizeof(json), event, ++sequence_number,
                              wall_ns, dropped_events);
    if (length == 0 || fwrite(json, 1, length, event_output) != length ||
        fputc('\n', event_output) == EOF || fflush(event_output) == EOF) {
        fprintf(stderr, "tripwire: failed to serialize/write event: %s\n",
                strerror(errno ? errno : EIO));
        output_error = 1;
        return -1;
    }
    return 0;
}

static int handle_ring_event(void *context, void *data, size_t data_size)
{
    const struct tripwire_event *event = data;

    (void)context;
    if (data_size != sizeof(*event)) {
        fprintf(stderr, "tripwire: unexpected ring record size %zu (expected %zu)\n",
                data_size, sizeof(*event));
        output_error = 1;
        return -1;
    }
    return write_record(event, 0);
}

static int emit_stats(uint64_t cgroup_id, uint64_t ring_bytes,
                      uint64_t poll_interval_ms, int lost_map_fd,
                      uint64_t *per_cpu, int cpu_count,
                      uint64_t *last_reported_drops)
{
    struct tripwire_event event = {0};
    uint32_t zero = 0;
    uint64_t total = 0;
    int i;

    if (bpf_map_lookup_elem(lost_map_fd, &zero, per_cpu) != 0) {
        fprintf(stderr, "tripwire: read lost_events map: %s\n", strerror(errno));
        return -1;
    }
    for (i = 0; i < cpu_count; i++)
        total += per_cpu[i];

    event.type = TW_STATS;
    event.monotonic_ns = clock_ns(CLOCK_MONOTONIC);
    event.pid = (uint32_t)getpid();
    event.tgid = (uint32_t)getpid();
    event.ppid = (uint32_t)getppid();
    event.uid = (uint32_t)getuid();
    event.cgroup_id = cgroup_id;
    event.ring_buffer_bytes = ring_bytes;
    event.path_bytes = TRIPWIRE_PATH_BYTES;
    event.poll_interval_ms = poll_interval_ms;
    if (prctl(PR_GET_NAME, event.comm, 0, 0, 0) != 0)
        memcpy(event.comm, "tripwire", sizeof("tripwire"));
    if (write_record(&event, total) != 0)
        return -1;
    *last_reported_drops = total;
    return 0;
}

static int attach_tracepoints(struct tripwire_bpf *skel,
                              struct bpf_link **links, size_t link_capacity,
                              size_t *link_count)
{
    struct bpf_program *program;

    bpf_object__for_each_program(program, skel->obj) {
        const char *section = bpf_program__section_name(program);
        const char *category;
        const char *name;
        const char *slash;
        char category_copy[64];
        struct bpf_link *link;
        size_t category_length;

        if (section == NULL || strncmp(section, "tracepoint/", 11) != 0)
            continue;
        category = section + 11;
        slash = strchr(category, '/');
        if (slash == NULL || slash == category || slash[1] == '\0') {
            fprintf(stderr, "tripwire: malformed tracepoint section: %s\n", section);
            return -1;
        }
        category_length = (size_t)(slash - category);
        if (category_length >= sizeof(category_copy)) {
            fprintf(stderr, "tripwire: tracepoint category too long: %s\n", section);
            return -1;
        }
        memcpy(category_copy, category, category_length);
        category_copy[category_length] = '\0';
        name = slash + 1;
        if (*link_count >= link_capacity) {
            fprintf(stderr, "tripwire: tracepoint link limit exceeded\n");
            return -1;
        }
        link = bpf_program__attach_tracepoint(program, category_copy, name);
        if (libbpf_get_error(link)) {
            int error = (int)-libbpf_get_error(link);
            fprintf(stderr, "tripwire: attach %s: %s\n", section, strerror(error));
            return -1;
        }
        links[(*link_count)++] = link;
    }
    if (*link_count < 32) {
        fprintf(stderr, "tripwire: attached %zu tracepoints; expected at least 32\n",
                *link_count);
        return -1;
    }
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s --cgroup-id ID --output FILE --ring-bytes BYTES --poll-ms MS\n",
            program);
}

int main(int argc, char **argv)
{
    static const struct option options[] = {
        {"cgroup-id", required_argument, NULL, 'c'},
        {"output", required_argument, NULL, 'o'},
        {"ring-bytes", required_argument, NULL, 'r'},
        {"poll-ms", required_argument, NULL, 'p'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    struct tripwire_bpf *skel = NULL;
    struct ring_buffer *ring = NULL;
    struct bpf_link *links[MAX_TRACEPOINTS] = {0};
    uint64_t *per_cpu_drops = NULL;
    uint64_t cgroup_id = 0, ring_bytes = 16777216, poll_interval_ms = 1000;
    uint64_t last_reported_drops = 0;
    size_t link_count = 0;
    const char *output_path = NULL;
    int cpu_count = 0, option, result = EXIT_FAILURE;
    int64_t offset_signed;

    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (option) {
        case 'c':
            if (parse_u64(optarg, &cgroup_id) != 0) {
                fprintf(stderr, "tripwire: invalid cgroup ID: %s\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'o': output_path = optarg; break;
        case 'r':
            if (parse_u64(optarg, &ring_bytes) != 0) {
                fprintf(stderr, "tripwire: invalid ring size: %s\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'p':
            if (parse_u64(optarg, &poll_interval_ms) != 0) {
                fprintf(stderr, "tripwire: invalid poll interval: %s\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'h': usage(argv[0]); return EXIT_SUCCESS;
        default: usage(argv[0]); return EXIT_FAILURE;
        }
    }
    if (optind != argc || cgroup_id == 0 || output_path == NULL ||
        ring_bytes < MIN_RING_BYTES || (ring_bytes & (ring_bytes - 1)) != 0 ||
        poll_interval_ms == 0 || poll_interval_ms > 60000) {
        usage(argv[0]);
        fprintf(stderr, "tripwire: require cgroup ID, output, power-of-two ring >= 4096, poll interval 1..60000 ms\n");
        return EXIT_FAILURE;
    }

    if (strcmp(output_path, "-") == 0)
        event_output = stdout;
    else {
        event_output = fopen(output_path, "w");
        if (event_output == NULL) {
            fprintf(stderr, "tripwire: open %s: %s\n", output_path, strerror(errno));
            return EXIT_FAILURE;
        }
    }
    offset_signed = (int64_t)clock_ns(CLOCK_REALTIME) -
                    (int64_t)clock_ns(CLOCK_MONOTONIC);
    wall_offset_ns = (uint64_t)offset_signed;
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = tripwire_bpf__open();
    if (skel == NULL) {
        fprintf(stderr, "tripwire: open BPF skeleton failed\n");
        goto cleanup;
    }
    skel->rodata->target_cgroup_id = cgroup_id;
    if (bpf_map__set_max_entries(skel->maps.events, (uint32_t)ring_bytes) != 0) {
        fprintf(stderr, "tripwire: configure ring buffer size failed\n");
        goto cleanup;
    }
    if (tripwire_bpf__load(skel) != 0) {
        fprintf(stderr, "tripwire: load CO-RE programs failed; see kernel verifier log\n");
        goto cleanup;
    }
    if (attach_tracepoints(skel, links, MAX_TRACEPOINTS, &link_count) != 0)
        goto cleanup;
    ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_ring_event,
                            NULL, NULL);
    if (ring == NULL) {
        fprintf(stderr, "tripwire: create ring buffer consumer failed: %s\n",
                strerror(errno));
        goto cleanup;
    }
    cpu_count = libbpf_num_possible_cpus();
    if (cpu_count <= 0) {
        fprintf(stderr, "tripwire: determine possible CPU count failed: %d\n",
                cpu_count);
        goto cleanup;
    }
    per_cpu_drops = calloc((size_t)cpu_count, sizeof(*per_cpu_drops));
    if (per_cpu_drops == NULL) {
        perror("tripwire: allocate drop-counter buffer");
        goto cleanup;
    }

    fprintf(stderr,
            "tripwire: attached %zu tracepoints; cgroup_id=%llu ring_buffer_bytes=%llu path_bytes=%u poll_interval_ms=%llu\n",
            link_count, (unsigned long long)cgroup_id,
            (unsigned long long)ring_bytes, TRIPWIRE_PATH_BYTES,
            (unsigned long long)poll_interval_ms);
    if (emit_stats(cgroup_id, ring_bytes, poll_interval_ms,
                   bpf_map__fd(skel->maps.lost_events), per_cpu_drops,
                   cpu_count, &last_reported_drops) != 0)
        goto cleanup;

    while (!stopping) {
        int poll_result = ring_buffer__poll(ring, (int)poll_interval_ms);
        if (poll_result < 0 && poll_result != -EINTR) {
            fprintf(stderr, "tripwire: ring buffer poll: %s\n",
                    strerror(-poll_result));
            goto cleanup;
        }
        if (output_error)
            goto cleanup;
        if (!stopping && emit_stats(cgroup_id, ring_bytes, poll_interval_ms,
                                    bpf_map__fd(skel->maps.lost_events),
                                    per_cpu_drops, cpu_count,
                                    &last_reported_drops) != 0)
            goto cleanup;
    }
    if (emit_stats(cgroup_id, ring_bytes, poll_interval_ms,
                   bpf_map__fd(skel->maps.lost_events), per_cpu_drops,
                   cpu_count, &last_reported_drops) != 0)
        goto cleanup;
    result = output_error ? EXIT_FAILURE : EXIT_SUCCESS;

cleanup:
    free(per_cpu_drops);
    ring_buffer__free(ring);
    while (link_count > 0)
        bpf_link__destroy(links[--link_count]);
    tripwire_bpf__destroy(skel);
    if (event_output != NULL && event_output != stdout)
        fclose(event_output);
    return result;
}
