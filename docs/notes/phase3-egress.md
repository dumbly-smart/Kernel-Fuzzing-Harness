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

Unit tests pass for both cases. The validator accepted the observed UFW state
and the runner completed all 90 seeded records, but the 1 GiB guest OOM-killed
`llama-server` at 696032 kB anonymous RSS. A 1536 MiB guest later OOM-killed it
at 1218148 kB anonymous RSS. Those are model-runtime failures, not task
successes; both manifests record zero successes and must not be used as benign
corpus measurements. Two 2 GiB retries were stopped by the host headroom guard
at 3927 MiB and 3879 MiB available (required: 4096 MiB).

The VM runner now has an optional `--swap-mib` setting, defaulting to zero,
which provisions swap only inside the disposable guest before the experiment.
The value is recorded in host VM provenance. The next run will use 1536 MiB RAM
plus 1024 MiB guest swap; treat that configuration as an explicit model-memory
confound. Keep Phase 3 acceptance pending until all 90 runs have actual model
responses and the trace summary is reviewed.
