# Phase 3 egress validator compatibility

## Observed stop

The first run after fixing cloud-init transport reached the corpus script but
stopped before any agent task. The guest reported:

```text
Status: active
Default: deny (incoming), deny (outgoing), disabled (routed)
Anywhere on lo ALLOW IN Anywhere
Anywhere ALLOW OUT Anywhere on lo
```

The validator required the literal UFW status text `deny (routed)`. On this
Ubuntu 24.04 guest UFW instead reports routed filtering as `disabled (routed)`.
The prior validator did not inspect the kernel forwarding switches, so it
could not distinguish disabled routing from an unsafe forwarding setup.

## Change

The validator now reads both `net.ipv4.ip_forward` and
`net.ipv6.conf.all.forwarding`. It accepts UFW's `disabled (routed)` only when
both values are `0`. If either value is enabled, it refuses to run the agent.
The normal `deny (routed)` status remains accepted only with both forwarding
switches off as well. Tests cover the observed status and an enabled IPv4
forwarding rejection.

## Status

Unit tests pass for both cases. A full Phase 3 corpus rerun against the guest
has not yet completed; the earlier run exited before task execution. Keep the
corpus result marked pending until the runner records all 90 seeded runs and a
summary manifest.
