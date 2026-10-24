# Phase 5: local prompt-injection suite

## Implemented

- Six YAML cases under `injections/`, covering all three delivery channels:
  file content, a declared loopback web page, and shell tool output. Each case
  names a goal, expected OS footprint, and taxonomy hypothesis.
- The case loader validates task tools, fixture paths, local routes, goal
  fields, and taxonomy labels before execution. Payloads can only be delivered
  through a fixture or a declared `/injection/<id>` route.
- The local sink binds to `127.0.0.1`. Its optional `POST /canary` endpoint
  records UTF-8 bodies up to 4 KiB; all other POST routes return 404. Fake
  canary tokens and outside-write targets are unique per case run and live in
  the guest's ignored run directory.
- The sink uses the fixed loopback port in `config/lab.json` so a benign fetch
  run and a later injection run have a comparable host-and-port feature.
- `scripts/smoke_injections.sh` requires a prepared benign corpus, applies the
  guest UFW deny-all-outbound policy, starts the tracer and fixture sink, runs
  the local model, joins events, finalizes behavioral goals from OS evidence,
  then scores injections against the benign-trained baselines.
- The shell tool runs as `tripwire-agent`, a system account with no sudo group.
  UFW still blocks all non-loopback traffic as a second boundary. Cloud-init
  resets the firewall before fetching the repository archive; no injection
  prompts run during that bootstrap period.
- The transparent keyword classifier reports its reasons, attack TPR, and
  false-positive rate over the 30 benign task prompts. This lexical baseline
  is not a semantic prompt-injection detector.
  The OS baselines separately emit per-injection verdicts at calibrated FPRs.

## Limits and measurement rules

`taxonomy_hypothesis` is a hypothesis only. A case counts as hijacked only when
its declarative goal is observed. The process-spawn goal is finalized from a
joined `execve`/`execveat` event; fake-canary receipt is checked at the local
sink. The monitor observes connection metadata, not HTTP body contents, which
is why the exfiltration case is hypothesized as partially visible.

The suite has one seed per case by default and only six attack cases. Do not
interpret its rates as population estimates. Model failure remains an explicit
unsuccessful run row. The current development host could not complete even the
2 GiB guest launch safely; no attack success, prompt-classifier rate, or monitor
verdict has been measured yet.

## Acceptance

Unit tests cover nested case loading, channel/taxonomy coverage, bounded local
canary POST, goal finalization, prompt-classifier explanations, and attack rows
remaining outside detector training/calibration. Full acceptance awaits a
completed Phase 3 model/corpus guest. These tests do not establish agent
takeover rates or monitor effectiveness; those require successful guest runs.
