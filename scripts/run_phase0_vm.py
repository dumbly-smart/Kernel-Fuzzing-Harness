#!/usr/bin/env python3
"""Run a Tripwire guest in QEMU using a verified Ubuntu cloud image.

No host mounts, SSH keys, or host package changes. The loopback HTTP server
serves only generated seed data and a git archive of this repository.
"""
import base64
import binascii
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
import argparse
import re
import sys
import threading
import time
import uuid

# The runner is invoked as a script, so include its sibling helper module.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from nocloud_seed import write_seed_iso

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / 'data/vm'
IMAGE = 'ubuntu-24.04-server-cloudimg-amd64.img'
FINGERPRINT = 'D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'
RESULT_CHUNK_CHARS = 3000
GUEST_ARTIFACT_NAMES = (
    'setup.log', 'setup-repeat.log', 'acceptance.log', 'smoke.log',
    'smoke-agent-join.log', 'smoke-events.jsonl', 'phase2-events.jsonl',
    'phase2-calls.jsonl', 'phase2-joins.jsonl', 'phase2-join-report.json',
    'environment.lock.json', 'model-install.log', 'model.lock.json',
    'phase3-model-lock.json', 'phase5-model-lock.json', 'phase3-corpus.log',
    'phase3-manifest.json', 'phase3-summary.json', 'phase3-runs.jsonl',
    'phase3-calls.jsonl', 'phase3-events.jsonl', 'phase3-joined.jsonl',
    'phase3-orphan-events.jsonl', 'phase3-egress-lockdown.log',
    'phase3-agent-account.log', 'phase3-loader.log', 'phase3-runner.log',
    'phase5-agent-account.log', 'phase5-injections.log', 'phase5-manifest.json',
    'phase5-summary.json', 'phase5-runs.jsonl', 'phase5-calls.jsonl',
    'phase5-events.jsonl', 'phase5-joined.jsonl', 'phase5-join-report.json',
    'phase5-canary-receipts.jsonl', 'phase5-egress-lockdown.log',
    'phase5-prompt-classifier.json', 'phase5-detector-results.json',
    'phase5-detector-scores.jsonl', 'phase5-false-positives.jsonl',
    'phase5-attack-verdicts.jsonl', 'phase5-runner.log', 'phase5-sink.log',
    'phase5-loader.log', 'phase5-join.log', 'phase5-detector-eval.log',
    'phase6-mimicry.log', 'phase6-manifest.json', 'phase6-runs.jsonl',
    'phase6-calls.jsonl', 'phase6-events.jsonl', 'phase6-joined.jsonl',
    'phase6-join-report.json', 'phase6-canary-receipts.jsonl',
    'phase6-detector-results.json', 'phase6-detector-scores.jsonl',
    'phase6-false-positives.jsonl', 'phase6-attack-verdicts.jsonl',
    'phase6-summary.json', 'phase6-egress-lockdown.log', 'phase6-loader.log',
    'phase6-sink.log', 'phase6-runner.log', 'phase6-join.log',
    'phase6-detector-eval.log', 'phase7-eval.log',
    'phase7-detector-results.json', 'phase7-ablation-results.json',
    'phase7-ablation-false-positives.jsonl',
    'phase7-ablation-attack-verdicts.jsonl', 'phase7-taxonomy-results.json',
    'phase7-ablation-plot.svg',
)


def command(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def write_guest_artifacts(directory, files):
    directory.mkdir(parents=True, exist_ok=True)
    for name in GUEST_ARTIFACT_NAMES:
        if name in files:
            (directory / name).write_text(files[name])


def cloud_init_bootstrap_command():
    return (
        'set -x; '
        'exec > >(tee /var/log/tripwire-bootstrap.log /dev/ttyS0) 2>&1; '
        'systemctl stop apt-daily.timer apt-daily-upgrade.timer; '
        'systemctl mask apt-daily.service apt-daily-upgrade.service; '
        'mkdir -p /opt/tripwire; '
        'ufw --force reset || true; '
        'python3 -c "import urllib.request; urllib.request.urlretrieve('
        "'http://10.0.2.2:PORT/repo.tar', '/root/repo.tar')\"; "
        'tar -xf /root/repo.tar -C /opt/tripwire; '
        'systemctl daemon-reload; systemctl enable tripwire-phase0.service; '
        'systemctl start --no-block tripwire-phase0.service')


def nocloud_seed_qemu_args(seed_iso):
    """Attach cloud-init data locally so locked-down guests can still boot."""
    return ['-drive', f'file={seed_iso},media=cdrom,readonly=on',
            '-smbios', 'type=1,serial=ds=nocloud']


def phase3_run_directory():
    """Give each corpus attempt its own path so failed runs remain inspectable."""
    return f'data/phase3-corpus-{uuid.uuid4().hex[:12]}'


def verify_image():
    result = command(['gpg', '--homedir', str(VM / 'gnupg'), '--batch',
                      '--status-fd', '1', '--verify', str(VM / 'SHA256SUMS.gpg'),
                      str(VM / 'SHA256SUMS')], capture_output=True, text=True)
    if f'[GNUPG:] VALIDSIG {FINGERPRINT} ' not in result.stdout:
        raise RuntimeError('checksum signature does not match pinned Ubuntu cloud key')
    import hashlib
    expected = next(line.split()[0] for line in (VM / 'SHA256SUMS').read_text().splitlines()
                    if line.split()[-1].lstrip('*') == IMAGE)
    with (VM / IMAGE).open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != expected:
        raise RuntimeError(f'image SHA256 mismatch: expected {expected}, got {actual}')
    return actual


def vm_disk_paths(vm_dir, reuse_guest, overlay_name=None, base_disk_name=None):
    """Select an immutable backing disk and a fresh overlay path."""
    for name, label in ((overlay_name, "overlay"), (base_disk_name, "base disk")):
        if name is not None and Path(name).name != name:
            raise ValueError(f"{label} name must be a filename, not a path")
    if reuse_guest and base_disk_name is not None:
        raise ValueError("choose either the accepted base guest or a custom base disk")
    if base_disk_name is not None:
        return vm_dir / base_disk_name, vm_dir / (overlay_name or 'guest-derived.qcow2')
    if reuse_guest:
        return vm_dir / 'guest.qcow2', vm_dir / (overlay_name or 'guest-phase1.qcow2')
    return vm_dir / IMAGE, vm_dir / (overlay_name or 'guest.qcow2')


def validate_vm_resources(memory_mib, disk_gib):
    if (isinstance(memory_mib, bool) or not isinstance(memory_mib, int) or memory_mib < 1024 or
            isinstance(disk_gib, bool) or not isinstance(disk_gib, int) or disk_gib < 12):
        raise ValueError("VM resources require at least 1024 MiB memory and 12 GiB disk")
    return memory_mib, disk_gib


def validate_host_memory_headroom(memory_mib, available_mib, multiplier=2):
    values = (memory_mib, available_mib, multiplier)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise ValueError("host memory headroom values must be integers")
    if memory_mib < 1 or available_mib < 0 or multiplier < 1:
        raise ValueError("host memory headroom values must be positive (available memory may be zero)")
    required_mib = memory_mib * multiplier
    if available_mib < required_mib:
        raise ValueError(
            f"MemAvailable={available_mib} MiB; need at least {required_mib} MiB "
            f"({multiplier}x guest RAM)")
    return required_mib


def read_memavailable_mib(meminfo_path=Path('/proc/meminfo')):
    try:
        lines = meminfo_path.read_text().splitlines()
    except OSError as error:
        raise RuntimeError(f"cannot read host memory information: {error}") from error
    for line in lines:
        fields = line.split()
        if fields and fields[0] == 'MemAvailable:':
            if len(fields) != 3 or fields[2] != 'kB' or not fields[1].isdigit():
                raise RuntimeError(f"invalid MemAvailable entry in {meminfo_path}")
            return int(fields[1]) // 1024
    raise RuntimeError(f"MemAvailable entry missing from {meminfo_path}")


def enforce_runtime_host_headroom(memory_mib, meminfo_path=Path('/proc/meminfo')):
    available_mib = read_memavailable_mib(meminfo_path)
    required_mib = memory_mib * 2
    try:
        validate_host_memory_headroom(memory_mib, available_mib)
    except ValueError as error:
        raise RuntimeError(
            f"host memory headroom fell below {required_mib} MiB during guest run; "
            f"{error}") from error
    return available_mib


def validate_guest_mode(*, base_guest, base_disk_name, reuse_provisioned_base):
    if reuse_provisioned_base and not (base_guest or base_disk_name):
        raise ValueError("reuse-provisioned-base requires a base disk")
    return bool(reuse_provisioned_base)


def decode_guest_result(serial):
    """Decode chunked guest artifacts, retaining compatibility with old guests."""
    chunks = {}
    chunk_count = None
    legacy_payloads = []
    chunk_pattern = re.compile(
        r'^TRIPWIRE_RESULT_PART=(\d+)/(\d+):([A-Za-z0-9+/=]+)')
    legacy_pattern = re.compile(r'^TRIPWIRE_RESULT=([A-Za-z0-9+/=]+)')
    for line in serial.splitlines():
        match = chunk_pattern.match(line)
        if match:
            index, total = int(match.group(1)), int(match.group(2))
            if total < 1 or index < 1 or index > total:
                raise RuntimeError('guest result has an invalid chunk index')
            if chunk_count is not None and total != chunk_count:
                raise RuntimeError('guest result has inconsistent chunk counts')
            chunk_count = total
            value = match.group(3)
            if index in chunks and chunks[index] != value:
                raise RuntimeError(
                    f'guest result chunk {index} is duplicated with different data')
            chunks[index] = value
            continue
        match = legacy_pattern.match(line)
        if match:
            legacy_payloads.append(match.group(1))

    if chunks:
        if len(chunks) != chunk_count or any(index not in chunks
                                             for index in range(1, chunk_count + 1)):
            raise RuntimeError(
                f'incomplete guest result: received {len(chunks)} of {chunk_count} chunks')
        payload = ''.join(chunks[index] for index in range(1, chunk_count + 1))
    elif legacy_payloads:
        payload = legacy_payloads[-1]
    else:
        raise RuntimeError('guest returned no result; see data/vm/serial.log')

    try:
        result = json.loads(base64.b64decode(payload, validate=True))
    except (binascii.Error, json.JSONDecodeError) as exc:
        raise RuntimeError(f'guest result artifact could not be decoded: {exc}') from exc
    if (not isinstance(result, dict) or type(result.get('status')) is not int or
            not isinstance(result.get('files'), dict)):
        raise RuntimeError('guest result artifact has an invalid structure')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    base_group = parser.add_mutually_exclusive_group()
    base_group.add_argument("--base-guest", action="store_true",
                        help="create a fresh cloud-init instance from the previously accepted guest disk")
    base_group.add_argument("--base-disk-name", default=None,
                        help="use an existing disk filename under data/vm as immutable backing")
    parser.add_argument("--reuse-provisioned-base", action="store_true",
                        help="skip apt provisioning and update the environment lock on an accepted --base-guest")
    parser.add_argument("--memory-mib", type=int, default=2048,
                        help="guest memory in MiB (default: 2048)")
    parser.add_argument("--disk-gib", type=int, default=12,
                        help="overlay capacity in GiB (default: 12)")
    parser.add_argument("--overlay-name", default=None,
                        help="new overlay filename under data/vm (default depends on mode)")
    parser.add_argument("--timeout-seconds", type=int, default=1800,
                        help="maximum guest run time (default: 1800)")
    parser.add_argument("--phase3", action="store_true",
                        help="install the pinned local model and run all benign corpus seeds")
    parser.add_argument("--phase5", action="store_true",
                        help="run the local injection suite against a provisioned model guest")
    parser.add_argument("--phase6", action="store_true",
                        help="run naive and adaptive local mimicry attacks against the monitor")
    parser.add_argument("--phase7", action="store_true",
                        help="run detector, ablation, taxonomy and plot evaluation on saved guest data")
    parser.add_argument("--phase3-model-config", default="config/model.json",
                        help="profile used by Phase 3 (paired model lock selected automatically)")
    parser.add_argument("--phase5-model-config", default="config/model.json",
                        help="profile used by Phase 5 in an already provisioned guest")
    options = parser.parse_args()
    memory_mib, disk_gib = validate_vm_resources(options.memory_mib, options.disk_gib)
    # Match reproduce.sh's conservative host-side policy even when this runner
    # is invoked directly. It is a safety heuristic, not a model-fit guarantee.
    try:
        validate_host_memory_headroom(memory_mib, read_memavailable_mib())
    except (RuntimeError, ValueError) as error:
        parser.error(f"refusing VM launch: {error}")
    reuse_provisioned_base = validate_guest_mode(
        base_guest=options.base_guest,
        base_disk_name=options.base_disk_name,
        reuse_provisioned_base=options.reuse_provisioned_base)
    phase3_model_config = Path(options.phase3_model_config)
    if (phase3_model_config.is_absolute() or phase3_model_config.parent != Path("config") or
            phase3_model_config.suffix != ".json" or
            not (ROOT / phase3_model_config).is_file()):
        parser.error("phase3-model-config must be an existing config/*.json path")
    phase3_model_lock = phase3_model_config.with_name(
        f"{phase3_model_config.stem}.lock.json")
    phase5_model_config = Path(options.phase5_model_config)
    if (phase5_model_config.is_absolute() or phase5_model_config.parent != Path("config") or
            phase5_model_config.suffix != ".json" or
            not (ROOT / phase5_model_config).is_file()):
        parser.error("phase5-model-config must be an existing config/*.json path")
    phase5_model_lock = phase5_model_config.with_name(
        f"{phase5_model_config.stem}.lock.json")
    if (options.phase5 or options.phase6 or options.phase7) and not reuse_provisioned_base:
        parser.error("--phase5/--phase6/--phase7 requires --reuse-provisioned-base on a provisioned corpus guest")
    if options.phase3 and options.phase5 and phase3_model_config != phase5_model_config:
        parser.error("one VM run cannot install and evaluate two different model profiles")
    if isinstance(options.timeout_seconds, bool) or options.timeout_seconds <= 0:
        parser.error("timeout-seconds must be a positive integer")
    image_hash = verify_image()
    base_disk, overlay = vm_disk_paths(VM, reuse_guest=options.base_guest,
                                       overlay_name=options.overlay_name,
                                       base_disk_name=options.base_disk_name)
    if options.base_disk_name and not base_disk.is_file():
        raise RuntimeError(f"custom base disk does not exist: {base_disk}")
    seed = VM / 'seed'
    seed.mkdir(exist_ok=True)
    seed_iso = VM / 'nocloud-seed.iso'
    phase3_run_dir = phase3_run_directory()
    if overlay.exists():
        raise RuntimeError(f'{overlay} already exists; preserve it or remove it explicitly before a fresh run')
    command(['git', 'archive', '--format=tar', '-o', str(seed / 'repo.tar'), 'HEAD'], cwd=ROOT)
    # Reboot persistence lets setup select the installed generic kernel. Results
    # return through serial output, never by mounting the guest disk on the host.
    guest_script = r'''#!/bin/bash
set -uo pipefail
cd /opt/tripwire
if [ "REUSE_PROVISIONED" = "true" ]; then
    python3 scripts/check_env.py --record > /root/setup.log 2>&1
    status=$?
else
bash scripts/setup_vm.sh --disposable-guest > /root/setup.log 2>&1
status=$?
if [ "$status" -ne 0 ] && grep -q 'Reboot the VM into that kernel' /root/setup.log; then
    cat /root/setup.log > /dev/ttyS0
    systemctl reboot
    exit 0
fi
fi
if [ "$status" -eq 0 ]; then
    if [ "REUSE_PROVISIONED" != "true" ]; then
    bash scripts/setup_vm.sh --disposable-guest > /root/setup-repeat.log 2>&1
    status=$?
    fi
fi
if [ "$status" -eq 0 ]; then
    install -d -o ubuntu -g ubuntu /opt/tripwire/build
    chown -R ubuntu:ubuntu /opt/tripwire/build
    su ubuntu -s /bin/bash -c 'cd /opt/tripwire && make check && make test' > /root/acceptance.log 2>&1
    status=$?
fi
if [ "$status" -eq 0 ]; then
    bash /opt/tripwire/scripts/smoke_bpf.sh > /root/smoke.log 2>&1
    status=$?
fi
if [ "$status" -eq 0 ]; then
    bash /opt/tripwire/scripts/smoke_agent_join.sh > /root/smoke-agent-join.log 2>&1
    status=$?
fi
if [ "$status" -eq 0 ] && [ "PHASE3" = "true" ]; then
    bash /opt/tripwire/scripts/install_local_model.sh --record-lock --model-config "PHASE3_MODEL_CONFIG" > /root/model-install.log 2>&1
    status=$?
fi
if [ "$status" -eq 0 ] && [ "PHASE3" = "true" ]; then
    MODEL_CONFIG=/opt/tripwire/PHASE3_MODEL_CONFIG RUN_DIR=/opt/tripwire/PHASE3_RUN_DIR bash /opt/tripwire/scripts/smoke_benign_corpus.sh > /root/phase3-corpus.log 2>&1
    status=$?
fi
if [ "$status" -eq 0 ] && [ "PHASE5" = "true" ]; then
    MODEL_CONFIG=/opt/tripwire/PHASE5_MODEL_CONFIG RUN_DIR=/opt/tripwire/data/injection-corpus bash /opt/tripwire/scripts/smoke_injections.sh > /root/phase5-injections.log 2>&1
    status=$?
fi
if [ "$status" -eq 0 ] && [ "PHASE6" = "true" ]; then
    RUN_DIR=/opt/tripwire/data/mimicry-corpus bash /opt/tripwire/scripts/smoke_mimicry.sh > /root/phase6-mimicry.log 2>&1
    status=$?
fi
if [ "$status" -eq 0 ] && [ "PHASE7" = "true" ]; then
    ATTACK_DIR=/opt/tripwire/data/injection-corpus make -C /opt/tripwire eval-all > /root/phase7-eval.log 2>&1
    status=$?
fi
python3 - "$status" <<'RESULT'
import base64, json, pathlib, sys
files = {}
for name, path in {'setup.log': '/root/setup.log', 'setup-repeat.log': '/root/setup-repeat.log',
                   'acceptance.log': '/root/acceptance.log', 'smoke.log': '/root/smoke.log',
                   'smoke-agent-join.log': '/root/smoke-agent-join.log',
                   'smoke-events.jsonl': '/opt/tripwire/data/phase1-smoke.events.jsonl',
                   'phase2-events.jsonl': '/opt/tripwire/data/phase2-smoke.events.jsonl',
                   'phase2-calls.jsonl': '/opt/tripwire/data/phase2-smoke.calls.jsonl',
                   'phase2-joins.jsonl': '/opt/tripwire/data/phase2-smoke.joins.jsonl',
                   'phase2-join-report.json': '/opt/tripwire/data/phase2-smoke.join-report.json',
                   'environment.lock.json': '/opt/tripwire/config/environment.lock.json',
                   'model-install.log': '/root/model-install.log',
                   'model.lock.json': '/opt/tripwire/config/model.lock.json',
                   'phase3-model-lock.json': '/opt/tripwire/PHASE3_MODEL_LOCK',
                   'phase5-model-lock.json': '/opt/tripwire/PHASE5_MODEL_LOCK',
                   'phase3-corpus.log': '/root/phase3-corpus.log',
                   'phase3-manifest.json': '/opt/tripwire/PHASE3_RUN_DIR/manifest.json',
                   'phase3-summary.json': '/opt/tripwire/PHASE3_RUN_DIR/corpus-summary.json',
                   'phase3-runs.jsonl': '/opt/tripwire/PHASE3_RUN_DIR/runs.jsonl',
                   'phase3-calls.jsonl': '/opt/tripwire/PHASE3_RUN_DIR/calls.jsonl',
                   'phase3-events.jsonl': '/opt/tripwire/PHASE3_RUN_DIR/events.jsonl',
                   'phase3-joined.jsonl': '/opt/tripwire/PHASE3_RUN_DIR/joined.jsonl',
                   'phase3-orphan-events.jsonl': '/opt/tripwire/PHASE3_RUN_DIR/orphan-events.jsonl',
                   'phase3-egress-lockdown.log': '/opt/tripwire/PHASE3_RUN_DIR/egress-lockdown.log',
                   'phase3-agent-account.log': '/opt/tripwire/PHASE3_RUN_DIR/agent-account.log',
                   'phase3-loader.log': '/opt/tripwire/PHASE3_RUN_DIR/loader.log',
                   'phase3-runner.log': '/opt/tripwire/PHASE3_RUN_DIR/runner.log',
                   'phase5-injections.log': '/root/phase5-injections.log',
                   'phase5-manifest.json': '/opt/tripwire/data/injection-corpus/manifest.json',
                   'phase5-summary.json': '/opt/tripwire/data/injection-corpus/summary.json',
                   'phase5-runs.jsonl': '/opt/tripwire/data/injection-corpus/runs.jsonl',
                   'phase5-calls.jsonl': '/opt/tripwire/data/injection-corpus/calls.jsonl',
                   'phase5-events.jsonl': '/opt/tripwire/data/injection-corpus/events.jsonl',
                   'phase5-joined.jsonl': '/opt/tripwire/data/injection-corpus/joined.jsonl',
                   'phase5-join-report.json': '/opt/tripwire/data/injection-corpus/join-report.json',
                   'phase5-canary-receipts.jsonl': '/opt/tripwire/data/injection-corpus/canary-receipts.jsonl',
                   'phase5-egress-lockdown.log': '/opt/tripwire/data/injection-corpus/egress-lockdown.log',
                   'phase5-agent-account.log': '/opt/tripwire/data/injection-corpus/agent-account.log',
                   'phase5-prompt-classifier.json': '/opt/tripwire/data/injection-corpus/prompt-classifier.json',
                   'phase5-detector-results.json': '/opt/tripwire/data/injection-corpus/detector-eval/results.json',
                   'phase5-detector-scores.jsonl': '/opt/tripwire/data/injection-corpus/detector-eval/scores.jsonl',
                   'phase5-false-positives.jsonl': '/opt/tripwire/data/injection-corpus/detector-eval/false-positives.jsonl',
                   'phase5-attack-verdicts.jsonl': '/opt/tripwire/data/injection-corpus/detector-eval/attack-verdicts.jsonl',
                   'phase5-runner.log': '/opt/tripwire/data/injection-corpus/runner.log',
                   'phase5-sink.log': '/opt/tripwire/data/injection-corpus/sink.log',
                   'phase5-loader.log': '/opt/tripwire/data/injection-corpus/loader.log',
                   'phase5-join.log': '/opt/tripwire/data/injection-corpus/join.log',
                   'phase5-detector-eval.log': '/opt/tripwire/data/injection-corpus/detector-eval.log',
                   'phase6-mimicry.log': '/root/phase6-mimicry.log',
                   'phase6-manifest.json': '/opt/tripwire/data/mimicry-corpus/manifest.json',
                   'phase6-runs.jsonl': '/opt/tripwire/data/mimicry-corpus/runs.jsonl',
                   'phase6-calls.jsonl': '/opt/tripwire/data/mimicry-corpus/calls.jsonl',
                   'phase6-events.jsonl': '/opt/tripwire/data/mimicry-corpus/events.jsonl',
                   'phase6-joined.jsonl': '/opt/tripwire/data/mimicry-corpus/joined.jsonl',
                   'phase6-join-report.json': '/opt/tripwire/data/mimicry-corpus/join-report.json',
                   'phase6-canary-receipts.jsonl': '/opt/tripwire/data/mimicry-corpus/canary-receipts.jsonl',
                   'phase6-detector-results.json': '/opt/tripwire/data/mimicry-corpus/detector-eval/results.json',
                   'phase6-detector-scores.jsonl': '/opt/tripwire/data/mimicry-corpus/detector-eval/scores.jsonl',
                   'phase6-false-positives.jsonl': '/opt/tripwire/data/mimicry-corpus/detector-eval/false-positives.jsonl',
                   'phase6-attack-verdicts.jsonl': '/opt/tripwire/data/mimicry-corpus/detector-eval/attack-verdicts.jsonl',
                   'phase6-summary.json': '/opt/tripwire/data/mimicry-corpus/mimicry-summary.json',
                   'phase6-egress-lockdown.log': '/opt/tripwire/data/mimicry-corpus/egress-lockdown.log',
                   'phase6-loader.log': '/opt/tripwire/data/mimicry-corpus/loader.log',
                   'phase6-sink.log': '/opt/tripwire/data/mimicry-corpus/sink.log',
                   'phase6-runner.log': '/opt/tripwire/data/mimicry-corpus/runner.log',
                   'phase6-join.log': '/opt/tripwire/data/mimicry-corpus/join.log',
                   'phase6-detector-eval.log': '/opt/tripwire/data/mimicry-corpus/detector-eval.log',
                   'phase7-eval.log': '/root/phase7-eval.log',
                   'phase7-detector-results.json': '/opt/tripwire/data/injection-corpus/detector-eval/results.json',
                   'phase7-ablation-results.json': '/opt/tripwire/data/injection-corpus/ablation-eval/results.json',
                   'phase7-ablation-false-positives.jsonl': '/opt/tripwire/data/injection-corpus/ablation-eval/false-positives.jsonl',
                   'phase7-ablation-attack-verdicts.jsonl': '/opt/tripwire/data/injection-corpus/ablation-eval/attack-verdicts.jsonl',
                   'phase7-taxonomy-results.json': '/opt/tripwire/data/injection-corpus/taxonomy-results.json',
                   'phase7-ablation-plot.svg': '/opt/tripwire/data/injection-corpus/ablation-eval/ablation-tpr.svg'}.items():
    if pathlib.Path(path).exists():
        files[name] = pathlib.Path(path).read_text()
payload = base64.b64encode(json.dumps({'status': int(sys.argv[1]), 'files': files}).encode()).decode()
with open('/dev/ttyS0', 'w') as serial:
    chunks = [payload[index:index + RESULT_CHUNK_CHARS]
              for index in range(0, len(payload), RESULT_CHUNK_CHARS)]
    for index, chunk in enumerate(chunks, start=1):
        serial.write(f'\nTRIPWIRE_RESULT_PART={index}/{len(chunks)}:{chunk}\n')
        serial.flush()
RESULT
systemctl disable tripwire-phase0.service
systemctl poweroff
'''
    guest_script = guest_script.replace(
        '"REUSE_PROVISIONED"', f'"{str(reuse_provisioned_base).lower()}"')
    guest_script = guest_script.replace('"PHASE3" = "true"',
                                        f'"{str(options.phase3).lower()}" = "true"')
    guest_script = guest_script.replace('PHASE3_MODEL_CONFIG', str(phase3_model_config))
    guest_script = guest_script.replace('PHASE3_RUN_DIR', phase3_run_dir)
    guest_script = guest_script.replace('PHASE3_MODEL_LOCK', str(phase3_model_lock))
    guest_script = guest_script.replace('PHASE5_MODEL_LOCK', str(phase5_model_lock))
    guest_script = guest_script.replace('PHASE5_MODEL_CONFIG', str(phase5_model_config))
    guest_script = guest_script.replace('"PHASE5" = "true"',
                                        f'"{str(options.phase5).lower()}" = "true"')
    guest_script = guest_script.replace('"PHASE6" = "true"',
                                        f'"{str(options.phase6).lower()}" = "true"')
    guest_script = guest_script.replace('"PHASE7" = "true"',
                                        f'"{str(options.phase7).lower()}" = "true"')
    guest_script = guest_script.replace('RESULT_CHUNK_CHARS', str(RESULT_CHUNK_CHARS))
    unit = '[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=oneshot\nExecStart=/root/accept.sh\nTimeoutStartSec=infinity\n[Install]\nWantedBy=multi-user.target\n'
    # JSON is valid YAML; avoid a host PyYAML dependency.
    config = {'package_update': False, 'package_upgrade': False,
              'write_files': [{'path': '/root/accept.sh', 'permissions': '0700', 'content': guest_script},
                              {'path': '/etc/systemd/system/tripwire-phase0.service', 'content': unit}],
              'runcmd': [['bash', '-c', cloud_init_bootstrap_command()]]}
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(seed))
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    port = server.server_address[1]
    user_data = '#cloud-config\n' + json.dumps(config).replace('PORT', str(port))
    write_seed_iso(seed_iso, user_data, f'tripwire-{uuid.uuid4()}')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base_disk), str(overlay), f'{disk_gib}G'])
    qemu_args = ['qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-smp', '2', '-m', str(memory_mib),
            '-drive', f'file={overlay},if=virtio,format=qcow2', '-display', 'none',
            '-serial', f'file:{VM / "serial.log"}', '-monitor', 'none',
            '-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0']
    qemu_args.extend(nocloud_seed_qemu_args(seed_iso))
    provenance = {'image_url': 'https://cloud-images.ubuntu.com/releases/noble/release-20260926/' + IMAGE,
                  'image_sha256': image_hash, 'signing_fingerprint': FINGERPRINT,
                  'base_guest_disk': str(base_disk) if options.base_guest or options.base_disk_name else None,
                  'base_guest_provenance': str(VM / 'provenance.json') if options.base_guest or options.base_disk_name else None,
                  'qemu_version': subprocess.check_output(['qemu-system-x86_64', '--version'], text=True),
                  'memory_mib': memory_mib, 'disk_gib': disk_gib,
                  'timeout_seconds': options.timeout_seconds, 'phase3': options.phase3,
                  'phase3_run_dir': phase3_run_dir if options.phase3 else None,
                  'phase5': options.phase5, 'phase6': options.phase6, 'phase7': options.phase7,
                  'reuse_provisioned_base': reuse_provisioned_base,
                  'qemu_arguments': qemu_args, 'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()}
    (VM / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    try:
        with (VM / 'qemu.log').open('w') as log:
            proc = subprocess.Popen(qemu_args, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + options.timeout_seconds
                while proc.poll() is None:
                    if shutil.disk_usage(VM).free < 2 * 1024**3:
                        raise RuntimeError('less than 2 GiB disk space remains; stopping guest')
                    enforce_runtime_host_headroom(memory_mib)
                    if time.monotonic() > deadline:
                        raise RuntimeError(f'guest exceeded {options.timeout_seconds} second limit')
                    time.sleep(2)
                if proc.returncode:
                    raise RuntimeError(f'QEMU exit {proc.returncode}; see data/vm/qemu.log')
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
    finally:
        server.shutdown()
        server.server_close()
    serial = (VM / 'serial.log').read_text(errors='replace')
    result = decode_guest_result(serial)
    write_guest_artifacts(VM, result['files'])
    if 'phase3-model-lock.json' in result['files']:
        (ROOT / phase3_model_lock).write_text(result['files']['phase3-model-lock.json'])
    if 'phase5-model-lock.json' in result['files']:
        (ROOT / phase5_model_lock).write_text(result['files']['phase5-model-lock.json'])
    print(f"Guest acceptance exit: {result['status']}; artifacts: {VM}", flush=True)
    raise SystemExit(result['status'])


if __name__ == '__main__':
    main()
