#include "event_json.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct json_writer {
    char *output;
    size_t capacity;
    size_t length;
    int failed;
};

static void append_bytes(struct json_writer *writer, const char *bytes,
                         size_t length)
{
    if (writer->failed || length > writer->capacity - writer->length - 1) {
        writer->failed = 1;
        return;
    }
    memcpy(writer->output + writer->length, bytes, length);
    writer->length += length;
    writer->output[writer->length] = '\0';
}

static void append_format(struct json_writer *writer, const char *format, ...)
{
    int length;
    va_list args;

    if (writer->failed || writer->length >= writer->capacity) {
        writer->failed = 1;
        return;
    }
    va_start(args, format);
    length = vsnprintf(writer->output + writer->length,
                       writer->capacity - writer->length, format, args);
    va_end(args);
    if (length < 0 || (size_t)length >= writer->capacity - writer->length) {
        writer->failed = 1;
        return;
    }
    writer->length += (size_t)length;
}

static int continuation(unsigned char byte)
{
    return byte >= 0x80 && byte <= 0xbf;
}

static size_t bounded_length(const char *text, size_t maximum)
{
    size_t length = 0;
    while (length < maximum && text[length] != '\0')
        length++;
    return length;
}

/* Preserve valid UTF-8 and escape invalid path bytes so every line is JSON. */
static size_t utf8_width(const unsigned char *text, size_t remaining)
{
    unsigned char a;

    if (remaining == 0)
        return 0;
    a = text[0];
    if (a < 0x80)
        return 1;
    if (a >= 0xc2 && a <= 0xdf && remaining >= 2 && continuation(text[1]))
        return 2;
    if (remaining >= 3 && continuation(text[2])) {
        unsigned char b = text[1];
        if (((a == 0xe0 && b >= 0xa0 && b <= 0xbf) ||
             ((a >= 0xe1 && a <= 0xec) && continuation(b)) ||
             (a == 0xed && b >= 0x80 && b <= 0x9f) ||
             ((a >= 0xee && a <= 0xef) && continuation(b))))
            return 3;
    }
    if (remaining >= 4 && continuation(text[2]) && continuation(text[3])) {
        unsigned char b = text[1];
        if (((a == 0xf0 && b >= 0x90 && b <= 0xbf) ||
             ((a >= 0xf1 && a <= 0xf3) && continuation(b)) ||
             (a == 0xf4 && b >= 0x80 && b <= 0x8f)))
            return 4;
    }
    return 0;
}

static void append_string(struct json_writer *writer, const char *text,
                          size_t maximum)
{
    const unsigned char *bytes = (const unsigned char *)text;
    size_t length = bounded_length(text, maximum);
    size_t i = 0;

    append_bytes(writer, "\"", 1);
    while (i < length && !writer->failed) {
        unsigned char byte = bytes[i];
        if (byte == '"' || byte == '\\') {
            char escaped[2] = {'\\', (char)byte};
            append_bytes(writer, escaped, sizeof(escaped));
            i++;
        } else if (byte < 0x20) {
            append_format(writer, "\\u%04x", (unsigned int)byte);
            i++;
        } else if (byte < 0x80) {
            append_bytes(writer, (const char *)&bytes[i], 1);
            i++;
        } else {
            size_t width = utf8_width(bytes + i, length - i);
            if (width == 0) {
                append_format(writer, "\\u%04x", (unsigned int)byte);
                i++;
            } else {
                append_bytes(writer, (const char *)&bytes[i], width);
                i += width;
            }
        }
    }
    append_bytes(writer, "\"", 1);
}

static void append_address(struct json_writer *writer,
                           const struct tripwire_event *event)
{
    char address[INET6_ADDRSTRLEN];
    int family;
    size_t expected_length;

    if (event->family == AF_INET) {
        family = AF_INET;
        expected_length = 4;
    } else if (event->family == AF_INET6) {
        family = AF_INET6;
        expected_length = 16;
    } else {
        writer->failed = 1;
        return;
    }
    if (event->address_length != expected_length ||
        inet_ntop(family, event->address, address, sizeof(address)) == NULL) {
        writer->failed = 1;
        return;
    }
    append_format(writer, ",\"family\":%u,\"address\":",
                  (unsigned int)event->family);
    append_string(writer, address, sizeof(address));
    append_format(writer, ",\"port\":%u", (unsigned int)event->port);
}

size_t event_json_write(char *output, size_t capacity,
                        const struct tripwire_event *event,
                        __u64 sequence, __u64 wall_ns, __u64 dropped_events)
{
    struct json_writer writer = {output, capacity, 0, 0};
    const char *type;

    if (capacity == 0 || event == NULL || output == NULL)
        return 0;
    output[0] = '\0';
    switch (event->type) {
    case TW_SYSCALL: type = "syscall"; break;
    case TW_PROCESS_FORK: type = "process_fork"; break;
    case TW_PROCESS_EXIT: type = "process_exit"; break;
    case TW_STATS: type = "stats"; break;
    default: return 0;
    }
    append_format(&writer,
                  "{\"type\":\"%s\",\"sequence\":%llu,"
                  "\"monotonic_ns\":%llu,\"wall_ns\":%llu,"
                  "\"pid\":%u,\"tgid\":%u,\"ppid\":%u,\"uid\":%u,"
                  "\"cgroup_id\":%llu,\"comm\":",
                  type, (unsigned long long)sequence,
                  (unsigned long long)event->monotonic_ns,
                  (unsigned long long)wall_ns, event->pid, event->tgid,
                  event->ppid, event->uid,
                  (unsigned long long)event->cgroup_id);
    append_string(&writer, event->comm, sizeof(event->comm));

    if (event->type == TW_SYSCALL) {
        append_format(&writer,
                      ",\"syscall\":\"%.*s\",\"return_code\":%lld,"
                      "\"dirfd\":%d,\"fd\":%d,\"byte_count\":%llu",
                      (int)sizeof(event->syscall), event->syscall,
                      (long long)event->return_code, event->dirfd, event->fd,
                      (unsigned long long)event->byte_count);
        if (event->flags & TW_HAS_PATH) {
            append_bytes(&writer, ",\"path\":", sizeof(",\"path\":") - 1);
            append_string(&writer, event->path, sizeof(event->path));
        }
        if (event->flags & TW_HAS_PATH2) {
            append_bytes(&writer, ",\"path2\":", sizeof(",\"path2\":") - 1);
            append_string(&writer, event->path2, sizeof(event->path2));
        }
        if (event->flags & TW_HAS_ADDRESS)
            append_address(&writer, event);
        if (event->flags & (TW_PATH_TRUNCATED | TW_PATH2_TRUNCATED))
            append_format(&writer,
                          ",\"path_truncated\":%s,\"path2_truncated\":%s",
                          event->flags & TW_PATH_TRUNCATED ? "true" : "false",
                          event->flags & TW_PATH2_TRUNCATED ? "true" : "false");
    } else if (event->type == TW_PROCESS_FORK) {
        append_format(&writer, ",\"child_pid\":%u", event->child_pid);
    } else if (event->type == TW_STATS) {
        append_format(&writer,
                      ",\"dropped_events\":%llu,\"ring_buffer_bytes\":%llu,"
                      "\"path_bytes\":%u,\"poll_interval_ms\":%llu",
                      (unsigned long long)dropped_events,
                      (unsigned long long)event->ring_buffer_bytes,
                      event->path_bytes,
                      (unsigned long long)event->poll_interval_ms);
    }
    append_bytes(&writer, "}", 1);
    return writer.failed ? 0 : writer.length;
}
