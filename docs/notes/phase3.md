# Phase 3: local model and benign corpus

## Implementation choices

- The task files are YAML mappings parsed with the pinned Ubuntu `python3-yaml`
  package. A single declarative success check is evaluated after every run.
- Runs use the Ollama local chat API on `127.0.0.1`; the runtime archive and
  downloaded model manifest are recorded separately from the base BPF guest
  lock. Seed, temperature, context size, output cap, and turn cap are explicit.
- The local HTTP fixtures are served only on guest loopback from a process kept
  outside the agent cgroup. This leaves the agent's connect and receive events
  attributable to the agent without counting the fixture server's own syscalls.
- Failed model calls remain in `runs.jsonl` with the exact error. They count as
  utility failures and are not silently retried against another model or API.

## First guest attempt

The fresh 6 GiB RAM / 32 GiB overlay passed repeated setup, `make check`, all 62
unit tests, Phase 1 tracer smoke, and the 10-task Phase 2 join smoke. Model
installation stopped before downloading a model because the script requested
the nonexistent `ollama-linux-amd64.tgz` URL and GitHub returned HTTP 404
(`curl` exit 22). The pinned SHA was for the official
`ollama-linux-amd64.tar.zst` asset. The asset name is now explicit in
`config/model.json`; the corrected installer verifies the same SHA before
extracting it. No model inference or corpus runs occurred in that attempt.

The second guest downloaded and checksum-verified the 1.4 GiB release asset,
extracted it, started the loopback service, and received a successful
`/api/version` health response. It then stopped because `/usr/local/bin/ollama
--version` exited with status 2. The installer captured that command's output
inside shell substitution, so its stderr was not preserved in the returned log;
the trap reported the failing command but not the captured text. The health
check showed the service was responding, so version verification now reads the
server's `/api/version` JSON field, which checks the process actually serving
requests. No model pull or corpus run occurred in this attempt either.

Official pin source: <https://github.com/ollama/ollama/releases/expanded_assets/v0.40.7>.

## Acceptance

Pending a fresh guest run with the corrected asset name. Keep the exact model
manifest digest, 90 task outcomes, join metrics, dropped-event count, and
behavior summaries with the acceptance artifacts; do not fill these from
expected values.
