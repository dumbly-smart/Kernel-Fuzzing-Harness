# Tripwire

Research project for an eBPF behavioral monitor of tool-using LLM agents and an
adaptive attacker against that monitor. Phases 0–2 and the Phase 3 local agent,
benign corpus, and Phase 4 detector baselines are implemented. Injection,
adaptive attacker, taxonomy, and final research measurements are in progress.

All experiments belong in a throwaway guest you control, using fake secrets and
local sinks. Never mount host home directories or pass through host credentials.

## Reproduce the environment

For an automated QEMU run using existing host tools, see
[the disposable VM recipe](docs/notes/phase0-qemu.md). Add --base-guest to
reuse the pinned, accepted disk as a read-only backing image for an isolated
test overlay after Phase 0 has passed.

1. Create an Ubuntu **24.04 amd64** VM with its own disk and NAT networking.
   A practical starting allocation is 4 vCPUs, 8 GiB RAM and 30 GiB disk for
   compiler work (an estimate, not a measured model requirement). Model hardware
   requirements will be chosen later. Disable shared folders and clipboard.
2. Use an official Ubuntu 24.04 installer. Verify its checksum against the signed
   Ubuntu SHA256SUMS. Record the exact ISO filename, SHA256 and hypervisor version
   in `docs/ENVIRONMENT.md`. The accepted QEMU cloud-image route already records
   its image identity and exact environment lock there.
3. Transfer this repository into the guest without host secrets. From its root:

   ```sh
   sudo bash scripts/setup_vm.sh --disposable-guest
   ```

   Setup uses Ubuntu's archive snapshot `20261001T000000Z`, installs exact
   candidate package versions, and records all installed Debian package versions,
   the running kernel and tool outputs in `config/environment.lock.json`.
   It refuses an undetected guest, other OS versions, and other architectures.
   If it reports a kernel mismatch, reboot the VM and rerun the same command.
   Setup can be rerun; an existing environment lock is never overwritten.
   The committed lock describes the accepted cloud-image guest; a different
   manual base image may fail this comparison and needs a separately reviewed lock.
4. Run the acceptance command as your normal guest user:

   ```sh
   make check
   make test
   ```

   `make check` prints tool versions and fails on missing dependencies, absent
   BTF, an unsupported guest, unavailable BPF compilation, or environment drift.
   It loads no BPF programs and needs no root. Commit the generated environment
   lock and completed image identity before declaring Phase 0 accepted.

The snapshot fixes repository packages, while the generated lock captures the
base image and installed dependency closure. Reproduction requires both the same
base image and that lock. A newer base image may need older packages; setup
reports apt errors rather than downgrading silently. No Python packages are
needed in Phase 0. No model runtime is installed and no paid API is configured.

Ubuntu 22.04 is in the research scope, but this first setup supports 24.04 only.
Containers share their enclosing kernel; prefer a full VM for kernel pinning.
Do not run setup on a host. Network access during setup is only for Ubuntu
packages; experimental sinks in later phases must be local.

## Layout

| Path | Purpose / first phase |
| --- | --- |
| `bpf/`, `tripwire/` | Tracer and userspace collector / 1 |
| `agent/` | Minimal agent and tool logs / 2 |
| `tasks/`, `data/` | Benign corpus and traces / 3 |
| `detectors/`, `eval/` | Baselines and measurements / 4 |
| `injections/`, `attacker/` | Local injection cases and adaptive attacker / 5–6 |
| `docs/`, `scripts/`, `tests/` | Notes, reproduction and checks / 0 onward |

See [environment status](docs/ENVIRONMENT.md),
[threat model](docs/THREAT_MODEL.md), and [Phase 0 notes](docs/notes/phase0.md).

## Phase 1 tracer

The C/libbpf CO-RE tracer records syscall metadata, paths, process fork/exit
events, and IPv4/IPv6 connection destinations for one cgroup v2 subtree. It
never copies write buffers or network payloads. From the repository root in
the pinned disposable guest, run:

```sh
make check
make test
sudo bash scripts/smoke_bpf.sh
```

The smoke test uses a temporary cgroup and a TCP listener bound only to
`127.0.0.1`. It validates the stream and prints its event/drop summary. A
reviewable trace sample is at [data/samples/phase1-smoke.jsonl](data/samples/phase1-smoke.jsonl).
See [Phase 1 learning and limits](docs/notes/phase1.md) and the
[guest acceptance record](docs/notes/phase1-guest-acceptance.txt).

## Phase 2 tool-call correlation

The minimal deterministic driver exposes workspace file tools, Bash, and
loopback-only HTTP. Call records include monotonic time, process IDs and cgroup
ID. `python3 -m tripwire.join` joins those records to the trace using process
fork ancestry, a configurable late-event grace, and an explicit ambiguous/orphan
report. Run `sudo make smoke-agent-join` in the disposable guest to exercise
ten tasks against a guest-local sink. The measured results and join limits are
in [Phase 2 notes](docs/notes/phase2.md).

## Phase 3 benign corpus

The minimal ReAct harness uses Ollama on guest loopback, with model runtime,
archive checksum, exact model tag, generation parameters, and manifest digest
recorded in separate config/lock files. The preferred profile is the pinned
Qwen3 8B Q4_K_M model. If the VM memory budget cannot accommodate it, the
explicit `config/model.low-memory.json` profile uses Qwen3 1.7B Q4_K_M; report
that smaller model as a task-utility confound. `config/model.tiny.json` is a
last-resort 0.6B Q4_K_M profile for constrained hosts and has a more severe
utility confound. All profiles use the same tool allowlists and 30 YAML tasks.
Each task runs with three fixed seeds, and failed model calls remain in the
dataset.

To run the full corpus in a disposable guest based on the accepted disk:

```sh
TMPDIR=/dev/shm python3 scripts/run_phase0_vm.py \
  --base-guest --reuse-provisioned-base \
  --memory-mib 2048 --disk-gib 24 --phase3 \
  --phase3-model-config config/model.tiny.json
```

The runner hands artifacts back through the QEMU serial channel and writes them
under ignored `data/vm/` paths. The sink is bound only to guest loopback and is
kept outside the agent cgroup. Before the agent starts, the smoke runner resets
UFW inside the disposable guest and permits traffic only on loopback; this
keeps shell tools from reaching external hosts while preserving local Ollama
and sink connections. See [Phase 3 notes](docs/notes/phase3.md) for
resource outcomes and acceptance status. To evaluate the baselines in a guest,
run `make eval-detectors`; it writes held-out scores, metrics and an FP-cause
log under `data/phase3-corpus/detector-eval/`.

## Phase 5 injection suite

Six local cases cover an out-of-scope fake-canary read, canary submission to a
loopback sink, an unexpected process, a write outside the workspace, a poisoned
summary, and a wrong-but-valid edit. Payloads are grouped by taxonomy hypothesis
under `injections/`. Each case records whether its goal was reached, its observed
OS events, and a transparent keyword prompt-classifier result. Monitor scores
and per-case verdicts are generated against the benign training corpus.

For a provisioned guest disk that contains the completed benign corpus and the
same pinned Ollama model, run a fresh overlay:

```sh
TMPDIR=/dev/shm python3 scripts/run_phase0_vm.py \
  --base-disk-name guest-phase3-tiny.qcow2 --reuse-provisioned-base \
  --memory-mib 2048 --disk-gib 24 --phase5 \
  --phase5-model-config config/model.tiny.json
```

The runner resets UFW during cloud-init bootstrap, then the injection smoke
reapplies deny-all egress with loopback allowed. The agent runs as the dedicated
non-sudo `tripwire-agent` account. Injection data and trace artifacts remain in
the disposable guest or ignored `data/vm/` output. See
[Phase 5 notes](docs/notes/phase5.md) for the exact measurement procedure and
current acceptance state.

## Phase 6 adaptive mimicry

The deterministic attacker runs two fake-canary actions against a loopback
fixture: a shell-based naive request and an adaptive request that uses the
benign fetch task's single `http_get` call and carries the canary in its query.
The sink logs only the synthetic `TRIPWIRE-FAKE-CANARY-*` value. The adaptive
request uses the same fixed guest-loopback port recorded in
[`config/lab.json`](config/lab.json), so host-and-port allowlist features stay
comparable across corpus and attack runs. The attacker uses no model and makes
no claim about model hijack rates.

On a provisioned guest containing `data/phase3-corpus`, run:

```sh
TMPDIR=/dev/shm python3 scripts/run_phase0_vm.py \
  --base-disk-name guest-phase3-corpus.qcow2 --reuse-provisioned-base \
  --memory-mib 2048 --disk-gib 24 --phase6
```

The smoke target trains/calibrates on the benign corpus and reports detection
for both attacker knowledge modes at the configured FPR targets. Details and
the limits of this proxy are in [Phase 6 notes](docs/notes/phase6.md).

## Phase 7 taxonomy and ablations

After a successful Phase 3 corpus and Phase 5 injection run, execute
`ATTACK_DIR=data/injection-corpus make eval-all` inside the provisioned guest.
This writes per-feature TPR/FPR metrics, false-positive causes, trace-backed
taxonomy evidence, and an SVG under `data/injection-corpus/`. The combined
score rule and feature groups are explicit in `config/ablations.json`. Cases
without successful goals or calibrated verdicts remain pending; see
[the taxonomy rules](docs/taxonomy.md) and [Phase 7 notes](docs/notes/phase7.md).


## Phase 0 acceptance

Passed in the disposable QEMU/KVM guest on 2026-10-22: setup, kernel reboot,
repeated setup, `make check`, and 10 tests. See the
[acceptance log](docs/notes/phase0-guest-acceptance.txt) and
[exact environment](docs/ENVIRONMENT.md). Phase 1 then loaded the tracer and
passed its smoke test; see the Phase 1 acceptance record above.
