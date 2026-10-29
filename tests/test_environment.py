"""Pure preflight tests; they install nothing and load no BPF programs."""
import importlib.util
from pathlib import Path
import subprocess
import json
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('check_env', Path(__file__).resolve().parents[1] / 'scripts/check_env.py')
env = importlib.util.module_from_spec(spec)
spec.loader.exec_module(env)


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.config = {'ubuntu_version': '24.04', 'minimum_kernel': [5, 15]}
        self.facts = dict(os=['ubuntu', '24.04'], architecture='x86_64',
                          kernel='6.8.0-100-generic', virtualization='kvm',
                          btf_readable=True, cgroup_fs='cgroup2fs')

    def test_supported_guest(self):
        self.assertEqual(env.validate(self.facts, self.config), [])

    def test_environment_lock_path_accepts_config_lock_files(self):
        self.assertEqual(
            env.resolve_environment_lock_path('config/environment.tcg.lock.json'),
            env.ROOT / 'config/environment.tcg.lock.json')

    def test_environment_lock_path_rejects_paths_outside_config(self):
        with self.assertRaisesRegex(ValueError, 'environment lock must be a config/\\*.json path'):
            env.resolve_environment_lock_path('../environment.lock.json')

    def test_tcg_lock_pins_the_observed_backend_and_same_guest_packages(self):
        config_dir = env.ROOT / 'config'
        kvm = json.loads((config_dir / 'environment.lock.json').read_text())
        tcg = json.loads((config_dir / 'environment.tcg.lock.json').read_text())
        expected = json.loads(json.dumps(kvm))
        expected['environment']['virtualization'] = 'qemu'

        self.assertEqual(tcg, expected)

    def test_host_and_missing_btf_are_errors(self):
        self.facts.update(virtualization='none', btf_readable=False)
        errors = env.validate(self.facts, self.config)
        self.assertTrue(any('disposable guest' in error for error in errors))
        self.assertTrue(any('vmlinux' in error for error in errors))

    def test_old_kernel_and_wrong_os(self):
        self.facts.update(kernel='5.14.0', os=['arch', None])
        self.assertEqual(len(env.validate(self.facts, self.config)), 2)

    def test_kernel_floor(self):
        self.facts['kernel'] = '5.15.0-generic'
        self.assertEqual(env.validate(self.facts, self.config), [])

    def test_command_failure_preserves_exact_error(self):
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess(
                ['bpftool'], 7, '', 'permission denied')):
            with self.assertRaisesRegex(RuntimeError, 'exit 7: permission denied'):
                env.run(['bpftool'])

    def test_missing_command(self):
        with patch.object(subprocess, 'run', side_effect=FileNotFoundError('missing executable')):
            with self.assertRaisesRegex(RuntimeError, 'clang-18: missing executable'):
                env.run(['clang-18'])

    def test_lock_detects_version_or_config_drift(self):
        original = {'configuration': self.config, 'environment': self.facts}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lock.json'
            path.write_text(json.dumps(original))
            self.assertTrue(env.lock_matches(path, original))
            changed = json.loads(json.dumps(original))
            changed['environment']['kernel'] = '6.8.0-101-generic'
            self.assertFalse(env.lock_matches(path, changed))
            changed = json.loads(json.dumps(original))
            changed['configuration']['ubuntu_version'] = '22.04'
            self.assertFalse(env.lock_matches(path, changed))

    def test_environment_lock_mismatch_lists_exact_differing_fields(self):
        expected = {
            'configuration': {'ubuntu_version': '24.04'},
            'environment': {'virtualization': 'kvm', 'kernel': '6.8.0'},
        }
        actual = {
            'configuration': {'ubuntu_version': '24.04'},
            'environment': {'virtualization': 'qemu', 'kernel': '6.9.0'},
        }

        self.assertEqual(env.describe_lock_differences(expected, actual), [
            "environment.kernel: expected '6.8.0', got '6.9.0'",
            "environment.virtualization: expected 'kvm', got 'qemu'",
        ])
