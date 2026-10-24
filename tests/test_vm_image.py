"""Verify that corrupt or incorrectly signed images cannot be booted."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('run_phase0_vm', Path(__file__).resolve().parents[1] / 'scripts/run_phase0_vm.py')
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class ImageVerificationTests(unittest.TestCase):
    def test_vm_resource_limits_accept_model_guest_size(self):
        self.assertEqual(vm.validate_vm_resources(6144, 32), (6144, 32))

    def test_vm_resource_limits_reject_too_small_or_invalid_values(self):
        for memory, disk in ((0, 32), (512, 32), (2048, 0), (2048, 8),
                             (True, 32), (2048, 12.5)):
            with self.subTest(memory=memory, disk=disk):
                with self.assertRaises(ValueError):
                    vm.validate_vm_resources(memory, disk)

    def test_base_guest_can_use_a_distinct_overlay_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'guest.qcow2').touch()
            base, overlay = vm.vm_disk_paths(root, reuse_guest=True,
                                             overlay_name='guest-phase3.qcow2')
            self.assertEqual(base, root / 'guest.qcow2')
            self.assertEqual(overlay, root / 'guest-phase3.qcow2')

    def test_failed_guest_can_be_used_as_an_immutable_base_for_a_fresh_overlay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'guest-phase3b.qcow2').touch()
            base, overlay = vm.vm_disk_paths(
                root, reuse_guest=False, base_disk_name='guest-phase3b.qcow2',
                overlay_name='guest-phase3c.qcow2')
            self.assertEqual(base, root / 'guest-phase3b.qcow2')
            self.assertEqual(overlay, root / 'guest-phase3c.qcow2')

    def test_custom_base_and_overlay_names_cannot_escape_vm_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'filename'):
                vm.vm_disk_paths(Path(directory), reuse_guest=False,
                                 base_disk_name='../guest.qcow2')

    def test_reuse_provisioned_guest_requires_base_guest_mode(self):
        self.assertTrue(vm.validate_guest_mode(base_guest=True,
                                               base_disk_name=None,
                                               reuse_provisioned_base=True))
        self.assertTrue(vm.validate_guest_mode(base_guest=False,
                                               base_disk_name='guest-phase3.qcow2',
                                               reuse_provisioned_base=True))
        with self.assertRaisesRegex(ValueError, 'requires a base disk'):
            vm.validate_guest_mode(base_guest=False, base_disk_name=None,
                                   reuse_provisioned_base=True)

    def test_base_guest_mode_preserves_baseline_and_uses_new_overlay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'guest.qcow2').touch()

            base, overlay = vm.vm_disk_paths(root, reuse_guest=True)

            self.assertEqual(base, root / 'guest.qcow2')
            self.assertEqual(overlay, root / 'guest-phase1.qcow2')
            self.assertTrue(base.exists())
            self.assertFalse(overlay.exists())

    def test_valid_image_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / vm.IMAGE
            image.write_bytes(b'fake test image')
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            (root / 'SHA256SUMS').write_text(f'{digest} *{vm.IMAGE}\n')
            signature = subprocess.CompletedProcess([], 0, f'[GNUPG:] VALIDSIG {vm.FINGERPRINT} 2026-09-26', '')
            with patch.object(vm, 'VM', root), patch.object(vm, 'command', return_value=signature):
                self.assertEqual(vm.verify_image(), digest)
                image.write_bytes(b'changed')
                with self.assertRaisesRegex(RuntimeError, 'SHA256 mismatch'):
                    vm.verify_image()

    def test_other_signer_rejected(self):
        result = subprocess.CompletedProcess([], 0, '[GNUPG:] VALIDSIG WRONGKEY ', '')
        with patch.object(vm, 'command', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'pinned Ubuntu cloud key'):
                vm.verify_image()

    def test_invalid_signature_rejected(self):
        with patch.object(vm, 'command', side_effect=subprocess.CalledProcessError(1, ['gpg'])):
            with self.assertRaises(subprocess.CalledProcessError):
                vm.verify_image()
