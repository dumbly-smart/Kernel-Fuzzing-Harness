"""Verify that corrupt or incorrectly signed images cannot be booted."""
import hashlib
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('run_phase0_vm', Path(__file__).resolve().parents[1] / 'scripts/run_phase0_vm.py')
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)

seed_spec = importlib.util.spec_from_file_location(
    'nocloud_seed', Path(__file__).resolve().parents[1] / 'scripts/nocloud_seed.py')
seed_iso = importlib.util.module_from_spec(seed_spec)
seed_spec.loader.exec_module(seed_iso)


class ImageVerificationTests(unittest.TestCase):
    def test_nocloud_seed_iso_has_cidata_label_and_both_required_files(self):
        user_data = '#cloud-config\n{}\n'
        with tempfile.TemporaryDirectory() as directory:
            image_path = Path(directory) / 'seed.iso'

            seed_iso.write_seed_iso(image_path, user_data, 'tripwire-run-123')

            image = image_path.read_bytes()
            self.assertGreaterEqual(len(image) // 2048, 300)
            descriptor = image[16 * 2048:17 * 2048]
            self.assertEqual(descriptor[:7], b'\x01CD001\x01')
            self.assertEqual(descriptor[40:46], b'CIDATA')
            root_extent = int.from_bytes(descriptor[158:162], 'little')
            root_size = int.from_bytes(descriptor[166:170], 'little')
            self.assertEqual(descriptor[881], 1)
            root = image[root_extent * 2048:root_extent * 2048 + root_size]
            self.assertEqual(int.from_bytes(root[10:14], 'little'), root_size)
            self.assertIn(b'USER-DATA;1', root)
            self.assertIn(b'META-DATA;1', root)
            files = {}
            offset = 0
            while offset < root_size and root[offset]:
                length = root[offset]
                entry = root[offset:offset + length]
                name_length = entry[32]
                name = entry[33:33 + name_length]
                if name not in (b'\x00', b'\x01'):
                    extent = int.from_bytes(entry[2:6], 'little')
                    size = int.from_bytes(entry[10:14], 'little')
                    files[name] = image[extent * 2048:extent * 2048 + size]
                offset += length
            self.assertEqual(files[b'USER-DATA;1'], user_data.encode())
            self.assertIn(b'instance-id: tripwire-run-123', files[b'META-DATA;1'])

    def test_nocloud_seed_iso_rejects_multiline_instance_id(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'single-line'):
                seed_iso.write_seed_iso(Path(directory) / 'seed.iso', '{}', 'bad\nid')

    def test_cloud_init_bootstrap_emits_commands_to_serial(self):
        command = vm.cloud_init_bootstrap_command()

        self.assertIn("set -x", command)
        self.assertIn("tee /var/log/tripwire-bootstrap.log /dev/ttyS0", command)
        self.assertIn("ufw --force reset", command)
        self.assertIn("10.0.2.2:PORT/repo.tar", command)
        self.assertLess(command.index('ufw --force reset'),
                        command.index('10.0.2.2:PORT/repo.tar'))

    def test_qemu_uses_local_nocloud_seed_medium(self):
        args = vm.nocloud_seed_qemu_args(Path('/tmp/tripwire-seed.iso'))

        self.assertEqual(args, [
            '-drive', 'file=/tmp/tripwire-seed.iso,media=cdrom,readonly=on',
            '-smbios', 'type=1,serial=ds=nocloud'])

    def test_phase3_run_directories_are_unique_and_inside_data(self):
        first = vm.phase3_run_directory()
        second = vm.phase3_run_directory()

        self.assertNotEqual(first, second)
        self.assertRegex(first, r'^data/phase3-corpus-[0-9a-f]{12}$')

    def test_persists_phase3_diagnostics_and_run_artifacts(self):
        artifacts = {
            "model-install.log": "Ollama ready\n",
            "phase3-corpus.log": "ERROR: egress setup failed\n",
            "phase3-runs.jsonl": '{"run_id":"one"}\n',
            "unapproved.txt": "do not write",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            vm.write_guest_artifacts(root, artifacts)

            self.assertEqual((root / "model-install.log").read_text(), "Ollama ready\n")
            self.assertEqual((root / "phase3-corpus.log").read_text(),
                             "ERROR: egress setup failed\n")
            self.assertEqual((root / "phase3-runs.jsonl").read_text(),
                             '{"run_id":"one"}\n')
            self.assertFalse((root / "unapproved.txt").exists())

    def test_make_check_scopes_python_bytecode_cache_by_user(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            ["make", "-n", "check"], cwd=root, check=True,
            capture_output=True, text=True)

        self.assertRegex(result.stdout, r"PYTHONPYCACHEPREFIX=.*id -u")

    def test_decodes_chunked_guest_result_with_interleaved_console_output(self):
        result = {"status": 2, "files": {"phase3.log": "x" * 30000}}
        payload = base64.b64encode(json.dumps(result).encode()).decode()
        chunk_chars = 3000
        chunks = [payload[i:i + chunk_chars]
                  for i in range(0, len(payload), chunk_chars)]
        serial = "\n".join(
            f"TRIPWIRE_RESULT_PART={index}/{len(chunks)}:{chunk}"
            if index == 1 else
            f"systemd status message\nTRIPWIRE_RESULT_PART={index}/{len(chunks)}:{chunk}"
            for index, chunk in enumerate(chunks, start=1))

        self.assertEqual(vm.decode_guest_result(serial), result)

    def test_decodes_legacy_single_line_guest_result(self):
        result = {"status": 0, "files": {}}
        payload = base64.b64encode(json.dumps(result).encode()).decode()

        self.assertEqual(vm.decode_guest_result(f"TRIPWIRE_RESULT={payload}\n"), result)

    def test_rejects_incomplete_chunked_guest_result(self):
        with self.assertRaisesRegex(RuntimeError, "incomplete guest result"):
            vm.decode_guest_result("TRIPWIRE_RESULT_PART=1/2:eyJzdGF0dXMi")

    def test_direct_runner_requires_twice_guest_memory_before_launch(self):
        self.assertEqual(vm.validate_host_memory_headroom(2048, 4096), 4096)
        self.assertEqual(vm.validate_host_memory_headroom(2048, 5000), 4096)
        with self.assertRaisesRegex(
                ValueError,
                r'MemAvailable=4095 MiB; need at least 4096 MiB \(2x guest RAM\)'):
            vm.validate_host_memory_headroom(2048, 4095)

    def test_direct_runner_rejects_invalid_headroom_values(self):
        for guest, available, multiplier in (
                (True, 4096, 2), (2048, False, 2), (2048, 4096, True),
                (0, 4096, 2), (2048, -1, 2), (2048, 4096, 0)):
            with self.subTest(guest=guest, available=available, multiplier=multiplier):
                with self.assertRaises(ValueError):
                    vm.validate_host_memory_headroom(guest, available, multiplier)

    def test_runtime_headroom_check_stops_when_available_memory_drops(self):
        with tempfile.TemporaryDirectory() as directory:
            meminfo = Path(directory) / "meminfo"
            meminfo.write_text("MemAvailable: 3000000 kB\n")

            with self.assertRaisesRegex(
                    RuntimeError,
                    r"host memory headroom fell below 4096 MiB during guest run; "
                    r"MemAvailable=2929 MiB"):
                vm.enforce_runtime_host_headroom(2048, meminfo)

    def test_runtime_headroom_check_allows_guest_when_memory_is_sufficient(self):
        with tempfile.TemporaryDirectory() as directory:
            meminfo = Path(directory) / "meminfo"
            meminfo.write_text("MemAvailable: 5120000 kB\n")

            self.assertEqual(vm.enforce_runtime_host_headroom(2048, meminfo), 5000)

    def test_memavailable_parser_reads_mib_and_reports_missing_or_malformed_value(self):
        with tempfile.TemporaryDirectory() as directory:
            meminfo = Path(directory) / 'meminfo'
            meminfo.write_text('MemTotal: 16384000 kB\nMemAvailable: 5120000 kB\n')
            self.assertEqual(vm.read_memavailable_mib(meminfo), 5000)
            meminfo.write_text('MemTotal: 16384000 kB\n')
            with self.assertRaisesRegex(RuntimeError, 'MemAvailable entry missing'):
                vm.read_memavailable_mib(meminfo)
            meminfo.write_text('MemAvailable: unknown kB\n')
            with self.assertRaisesRegex(RuntimeError, 'invalid MemAvailable entry'):
                vm.read_memavailable_mib(meminfo)

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
