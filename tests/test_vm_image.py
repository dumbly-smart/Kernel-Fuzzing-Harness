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
