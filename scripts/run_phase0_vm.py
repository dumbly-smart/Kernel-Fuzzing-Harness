#!/usr/bin/env python3
"""Run Phase 0 in QEMU using a separately verified Ubuntu cloud image.

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


def vm_disk_paths(vm_dir, reuse_guest):
    """Select an immutable backing disk and a fresh overlay path."""
    if reuse_guest:
        return vm_dir / 'guest.qcow2', vm_dir / 'guest-phase1.qcow2'
    return vm_dir / IMAGE, vm_dir / 'guest.qcow2'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-guest", action="store_true",
                        help="create a fresh cloud-init instance from the previously accepted guest disk")
    options = parser.parse_args()
    image_hash = verify_image()
    base_disk, overlay = vm_disk_paths(VM, reuse_guest=options.base_guest)
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
bash scripts/setup_vm.sh --disposable-guest > /root/setup.log 2>&1
status=$?
if [ "$status" -ne 0 ] && grep -q 'Reboot the VM into that kernel' /root/setup.log; then
    cat /root/setup.log > /dev/ttyS0
    systemctl reboot
    exit 0
fi
if [ "$status" -eq 0 ]; then
    bash scripts/setup_vm.sh --disposable-guest > /root/setup-repeat.log 2>&1
    status=$?
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
                   'environment.lock.json': '/opt/tripwire/config/environment.lock.json'}.items():
    if pathlib.Path(path).exists():
        files[name] = pathlib.Path(path).read_text()
payload = base64.b64encode(json.dumps({'status': int(sys.argv[1]), 'files': files}).encode()).decode()
with open('/dev/ttyS0', 'w') as serial:
    serial.write('\nTRIPWIRE_RESULT=' + payload + '\n')
RESULT
systemctl disable tripwire-phase0.service
systemctl poweroff
'''
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
    command(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base_disk), str(overlay), '12G'])
    qemu_args = ['qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-smp', '2', '-m', '2048',
            '-drive', f'file={overlay},if=virtio,format=qcow2', '-display', 'none',
            '-serial', f'file:{VM / "serial.log"}', '-monitor', 'none',
            '-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0',
            '-smbios', f'type=1,serial=ds=nocloud;s=http://10.0.2.2:{port}/']
    provenance = {'image_url': 'https://cloud-images.ubuntu.com/releases/noble/release-20260926/' + IMAGE,
                  'image_sha256': image_hash, 'signing_fingerprint': FINGERPRINT,
                  'base_guest_disk': str(base_disk) if options.base_guest else None,
                  'base_guest_provenance': str(VM / 'provenance.json') if options.base_guest else None,
                  'qemu_version': subprocess.check_output(['qemu-system-x86_64', '--version'], text=True),
                  'qemu_arguments': qemu_args, 'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()}
    (VM / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    try:
        with (VM / 'qemu.log').open('w') as log:
            proc = subprocess.Popen(qemu_args, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 1800
                while proc.poll() is None:
                    if shutil.disk_usage(VM).free < 2 * 1024**3:
                        raise RuntimeError('less than 2 GiB disk space remains; stopping guest')
                    if time.monotonic() > deadline:
                        raise RuntimeError('guest exceeded 30 minute limit')
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
