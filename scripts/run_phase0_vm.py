#!/usr/bin/env python3
"""Run a Tripwire guest in QEMU using a verified Ubuntu cloud image.

No host mounts, SSH keys, or host package changes. The loopback HTTP server
serves only generated seed data and a git archive of this repository.
"""
import base64
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
import argparse
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / 'data/vm'
IMAGE = 'ubuntu-24.04-server-cloudimg-amd64.img'
FINGERPRINT = 'D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'


def command(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


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


def validate_guest_mode(*, base_guest, reuse_provisioned_base):
    if reuse_provisioned_base and not base_guest:
        raise ValueError("reuse-provisioned-base requires --base-guest")
    return bool(reuse_provisioned_base)


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
    options = parser.parse_args()
    memory_mib, disk_gib = validate_vm_resources(options.memory_mib, options.disk_gib)
    reuse_provisioned_base = validate_guest_mode(
        base_guest=options.base_guest,
        reuse_provisioned_base=options.reuse_provisioned_base)
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
    if overlay.exists():
        raise RuntimeError(f'{overlay} already exists; preserve it or remove it explicitly before a fresh run')
    command(['git', 'archive', '--format=tar', '-o', str(seed / 'repo.tar'), 'HEAD'], cwd=ROOT)
    (seed / 'vendor-data').write_text('#cloud-config\n{}\n')
    (seed / 'meta-data').write_text(
        f'instance-id: tripwire-{uuid.uuid4()}\nlocal-hostname: tripwire\n')
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
    bash /opt/tripwire/scripts/install_local_model.sh --record-lock > /root/model-install.log 2>&1
    status=$?
fi
if [ "$status" -eq 0 ] && [ "PHASE3" = "true" ]; then
    RUN_DIR=/opt/tripwire/data/phase3-corpus bash /opt/tripwire/scripts/smoke_benign_corpus.sh > /root/phase3-corpus.log 2>&1
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
                   'phase3-corpus.log': '/root/phase3-corpus.log',
                   'phase3-manifest.json': '/opt/tripwire/data/phase3-corpus/manifest.json',
                   'phase3-summary.json': '/opt/tripwire/data/phase3-corpus/corpus-summary.json',
                   'phase3-runs.jsonl': '/opt/tripwire/data/phase3-corpus/runs.jsonl',
                   'phase3-calls.jsonl': '/opt/tripwire/data/phase3-corpus/calls.jsonl',
                   'phase3-events.jsonl': '/opt/tripwire/data/phase3-corpus/events.jsonl',
                   'phase3-joined.jsonl': '/opt/tripwire/data/phase3-corpus/joined.jsonl',
                   'phase3-orphan-events.jsonl': '/opt/tripwire/data/phase3-corpus/orphan-events.jsonl',
                   'phase3-loader.log': '/opt/tripwire/data/phase3-corpus/loader.log',
                   'phase3-runner.log': '/opt/tripwire/data/phase3-corpus/runner.log'}.items():
    if pathlib.Path(path).exists():
        files[name] = pathlib.Path(path).read_text()
payload = base64.b64encode(json.dumps({'status': int(sys.argv[1]), 'files': files}).encode()).decode()
with open('/dev/ttyS0', 'w') as serial:
    serial.write('\nTRIPWIRE_RESULT=' + payload + '\n')
RESULT
systemctl disable tripwire-phase0.service
systemctl poweroff
'''
    guest_script = guest_script.replace(
        '"REUSE_PROVISIONED"', f'"{str(reuse_provisioned_base).lower()}"')
    guest_script = guest_script.replace('"PHASE3" = "true"',
                                        f'"{str(options.phase3).lower()}" = "true"')
    unit = '[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=oneshot\nExecStart=/root/accept.sh\nTimeoutStartSec=infinity\n[Install]\nWantedBy=multi-user.target\n'
    # JSON is valid YAML; avoid a host PyYAML dependency.
    config = {'package_update': False, 'package_upgrade': False,
              'write_files': [{'path': '/root/accept.sh', 'permissions': '0700', 'content': guest_script},
                              {'path': '/etc/systemd/system/tripwire-phase0.service', 'content': unit}],
              'runcmd': [['bash', '-c', 'systemctl stop apt-daily.timer apt-daily-upgrade.timer; '
                         'systemctl mask apt-daily.service apt-daily-upgrade.service; '
                         'mkdir -p /opt/tripwire; '
                         'python3 -c "import urllib.request; urllib.request.urlretrieve(\'http://10.0.2.2:PORT/repo.tar\', \'/root/repo.tar\')"; '
                         'tar -xf /root/repo.tar -C /opt/tripwire; '
                         'systemctl daemon-reload; systemctl enable tripwire-phase0.service; '
                         'systemctl start --no-block tripwire-phase0.service']]}
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(seed))
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    port = server.server_address[1]
    (seed / 'user-data').write_text('#cloud-config\n' + json.dumps(config).replace('PORT', str(port)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base_disk), str(overlay), f'{disk_gib}G'])
    qemu_args = ['qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-smp', '2', '-m', str(memory_mib),
            '-drive', f'file={overlay},if=virtio,format=qcow2', '-display', 'none',
            '-serial', f'file:{VM / "serial.log"}', '-monitor', 'none',
            '-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0',
            '-smbios', f'type=1,serial=ds=nocloud;s=http://10.0.2.2:{port}/']
    provenance = {'image_url': 'https://cloud-images.ubuntu.com/releases/noble/release-20260926/' + IMAGE,
                  'image_sha256': image_hash, 'signing_fingerprint': FINGERPRINT,
                  'base_guest_disk': str(base_disk) if options.base_guest or options.base_disk_name else None,
                  'base_guest_provenance': str(VM / 'provenance.json') if options.base_guest or options.base_disk_name else None,
                  'qemu_version': subprocess.check_output(['qemu-system-x86_64', '--version'], text=True),
                  'memory_mib': memory_mib, 'disk_gib': disk_gib,
                  'timeout_seconds': options.timeout_seconds, 'phase3': options.phase3,
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
    results = [line.split('TRIPWIRE_RESULT=', 1)[1].strip() for line in serial.splitlines() if line.startswith('TRIPWIRE_RESULT=')]
    if not results:
        raise RuntimeError('guest returned no result; see data/vm/serial.log')
    result = json.loads(base64.b64decode(results[-1], validate=True))
    for name in ('setup.log', 'setup-repeat.log', 'acceptance.log', 'smoke.log',
                 'smoke-agent-join.log', 'smoke-events.jsonl', 'phase2-events.jsonl',
                 'phase2-calls.jsonl', 'phase2-joins.jsonl', 'phase2-join-report.json',
                 'environment.lock.json'):
        if name in result['files']:
            (VM / name).write_text(result['files'][name])
    print(f"Guest acceptance exit: {result['status']}; artifacts: {VM}", flush=True)
    raise SystemExit(result['status'])


if __name__ == '__main__':
    main()
