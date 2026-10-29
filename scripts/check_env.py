#!/usr/bin/env python3
"""Read-only preflight; --record creates the guest's exact environment lock once."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(argv):
    try:
        result = subprocess.run(argv, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise RuntimeError(f"{' '.join(argv)}: {exc}") from exc
    if result.returncode:
        raise RuntimeError(f"{' '.join(argv)}: exit {result.returncode}: "
                           f"{result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def validate(facts, config):
    errors = []
    if facts['os'] != ['ubuntu', config['ubuntu_version']]:
        errors.append(f"Ubuntu {config['ubuntu_version']} required; got {facts['os']}")
    if facts['architecture'] != 'x86_64':
        errors.append(f"amd64 required; got {facts['architecture']}")
    match = re.match(r'(\d+)\.(\d+)', facts['kernel'])
    if not match or tuple(map(int, match.groups())) < tuple(config['minimum_kernel']):
        errors.append(f"kernel >= 5.15 required; got {facts['kernel']}")
    if facts['virtualization'] in ('none', 'unavailable'):
        errors.append('no VM/container detected; disposable guest required')
    if not facts['btf_readable']:
        errors.append('/sys/kernel/btf/vmlinux missing or unreadable')
    if facts['cgroup_fs'] != 'cgroup2fs':
        errors.append('cgroup v2 required for the planned agent cgroup filter')
    return errors


def lock_matches(path, actual):
    return json.loads(path.read_text()) == actual


def describe_lock_differences(expected, actual):
    """Return stable, leaf-level diagnostics for a pinned lock mismatch."""
    missing = object()
    differences = []

    def walk(expected_value, actual_value, path):
        if isinstance(expected_value, dict) and isinstance(actual_value, dict):
            for key in sorted(expected_value.keys() | actual_value.keys()):
                child_path = f'{path}.{key}' if path else str(key)
                walk(expected_value.get(key, missing), actual_value.get(key, missing), child_path)
        elif expected_value != actual_value:
            expected_text = '<missing>' if expected_value is missing else repr(expected_value)
            actual_text = '<missing>' if actual_value is missing else repr(actual_value)
            differences.append(f'{path}: expected {expected_text}, got {actual_text}')

    walk(expected, actual, '')
    return differences


def resolve_environment_lock_path(path):
    """Resolve a named lock under config/ without accepting path escapes."""
    relative = Path(path)
    if (relative.is_absolute() or relative.parent != Path('config') or
            relative.suffix != '.json'):
        raise ValueError('environment lock must be a config/*.json path')
    resolved = (ROOT / relative).resolve()
    if not resolved.is_relative_to((ROOT / 'config').resolve()):
        raise ValueError('environment lock must be a config/*.json path')
    return resolved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', action='store_true')
    parser.add_argument('--lock-path',
                        default=os.environ.get('TRIPWIRE_ENVIRONMENT_LOCK',
                                               'config/environment.lock.json'))
    args = parser.parse_args()
    try:
        lock_path = resolve_environment_lock_path(args.lock_path)
    except ValueError as exc:
        parser.error(str(exc))
    config = json.loads((ROOT / 'config/environment.json').read_text())
    release = platform.freedesktop_os_release()
    facts = {'os': [release.get('ID'), release.get('VERSION_ID')],
             'architecture': platform.machine(), 'kernel': platform.release(),
             'btf_readable': os.access('/sys/kernel/btf/vmlinux', os.R_OK)}
    errors = []
    for key, command in {
        'virtualization': ['systemd-detect-virt'],
        'cgroup_fs': ['stat', '-fc', '%T', '/sys/fs/cgroup'],
        'clang': [config['clang'], '--version'],
        'libbpf': ['pkg-config', '--modversion', 'libbpf'],
        'bpftool': ['bpftool', 'version'],
        'python': ['python3', '--version'],
        'make': ['make', '--version'],
        'packages': ['dpkg-query', '-W', '-f=${binary:Package}=${Version}\n'],
    }.items():
        try:
            facts[key] = run(command)
            if key != 'packages':
                print(f"{key}: {facts[key]}")
        except RuntimeError as exc:
            facts[key] = 'unavailable'
            errors.append(str(exc))
    print(f"os: {facts['os']}; architecture: {facts['architecture']}")
    print(f"kernel: {facts['kernel']}; BTF readable: {facts['btf_readable']}")
    # Compile only: this checks LLVM's BPF backend without loading code into the kernel.
    try:
        with tempfile.TemporaryDirectory(prefix='tripwire-check-') as directory:
            run([config['clang'], '-target', 'bpf', '-O2', '-g', '-x', 'c',
                 '-c', '/dev/null', '-o', str(Path(directory) / 'probe.o')])
        print('clang BPF backend: PASS (compile only)')
    except RuntimeError as exc:
        errors.append(str(exc))
    errors.extend(validate(facts, config))
    actual = {'configuration': config, 'environment': facts}
    if lock_path.exists():
        if not lock_matches(lock_path, actual):
            expected = json.loads(lock_path.read_text())
            details = '; '.join(describe_lock_differences(expected, actual))
            errors.append(f'environment differs from {lock_path.relative_to(ROOT)}: {details}')
    elif args.record and not errors:
        with lock_path.open('x') as stream:
            json.dump(actual, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(f'created {lock_path.relative_to(ROOT)}; commit this lock with guest image identity')
    elif not args.record:
        errors.append('config/environment.lock.json missing; run setup inside the disposable guest')
    for error in errors:
        print(f'FAIL: {error}', file=sys.stderr)
    print(f"environment: {'FAIL' if errors else 'PASS'}")
    return int(bool(errors))


if __name__ == '__main__':
    sys.exit(main())
