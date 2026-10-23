#ifndef TRIPWIRE_EVENT_JSON_H
#define TRIPWIRE_EVENT_JSON_H

#include "event.h"
#include <stddef.h>

size_t event_json_write(char *output, size_t capacity,
                        const struct tripwire_event *event,
                        __u64 sequence, __u64 wall_ns, __u64 dropped_events);

#endif
