# Tripwire

Research scaffold for an eBPF behavioral monitor of tool-using LLM agents and an
adaptive attacker against that monitor. Phase 0 only: no tracer, agent, detector,
attacks, or experimental results exist yet.

All experiments belong in a throwaway guest you control, using fake secrets and
local sinks. Never mount host home directories or pass through host credentials.

## Reproduce the environment

For an automated QEMU run using existing host tools, see
[the disposable VM recipe](docs/notes/phase0-qemu.md).

1. Create an Ubuntu **24.04 amd64** VM with its own disk and NAT networking.
   A practical starting allocation is 4 vCPUs, 8 GiB RAM and 30 GiB disk for
   compiler work (an estimate, not a measured model requirement). Model hardware
   requirements will be chosen later. Disable shared folders and clipboard.
2. Use an official Ubuntu 24.04 installer. Verify its checksum against the signed
   Ubuntu SHA256SUMS. Record the exact ISO filename, SHA256 and hypervisor version
   in `docs/ENVIRONMENT.md`. These remain pending until a guest is provisioned.
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
