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
The value is recorded in host VM provenance. A 1024 MiB RAM plus 2048 MiB swap
run completed 90 records but OOM-killed the model after 11 tool calls; only 2
tasks succeeded, so it is not a usable corpus. A 3072 MiB swap request on the
12 GiB guest disk produced the exact error `fallocate failed: No space left on
device`. Bootstrap now fails immediately on swap setup errors and confirms that
at least one swap device is active before proceeding.

A 1024 MiB RAM plus 3072 MiB active swap run on a 16 GiB guest disk still
OOM-killed the model at 750712 kB anonymous RSS after three tasks succeeded;
the remaining records mostly captured model connection failures. This is not a
usable corpus.

The tiny profile now sets Ollama `keep_alive_seconds` to zero, which requests
that Ollama unload the model after each chat response. This runtime hypothesis
may add load latency and does not guarantee that one inference fits in memory.
The setting is passed by both evaluation runners and appears in each run's
generation provenance. Other model profiles leave it unset. The next measured
attempt repeated the 1024 MiB RAM plus 3072 MiB swap configuration on the
16 GiB disposable guest disk, but the host sent QEMU signal 15 after about 47
minutes. The exact host log was `qemu-system-x86_64: terminating on signal 15
from pid 912 (/usr/lib/systemd/systemd)`. No Tripwire result marker was
returned, so this is an interrupted attempt and its partial guest data is not
counted as corpus evidence.

Two higher-RAM retries stopped on the host headroom guard, not in the guest:
2048 MiB RAM plus 2048 MiB swap stopped at `MemAvailable=3462 MiB` (required
4096 MiB), and 1536 MiB RAM plus 3072 MiB swap stopped at
`MemAvailable=3063 MiB` (required 3072 MiB). The runner and its 2x-RAM guard
remain unchanged. A detached 1024 MiB RAM plus 3072 MiB swap retry reached
`tripwire-phase0.service`, but after 5h42m its overlay was only 90 MiB and the
guest serial had no result marker. Host TCP diagnostics showed an idle GitHub
connection in `LAST-ACK` and an `ESTAB` connection with retransmissions; the
guest had not returned its model-install log, so this is an infrastructure
stall, not a model or task failure. The run was stopped and its overlay kept.

The prior failed-run overlay contains the pinned Ollama 0.40.7 archive and a
complete Qwen3 model pull; its exported `model-install.log` reports each layer
at 100% and ends with the expected model tag. `install_local_model.sh` now
checks that the cached manifest matches the configured SHA256 lock and that
all referenced blobs are present before skipping `ollama pull`. Incomplete or
unmatched caches still follow the normal pull-and-verify path. The next run
will use a fresh overlay backed by that preserved model guest. Phase 3 remains
unaccepted until all 90 runs return model responses and the trace summary is
reviewed.
