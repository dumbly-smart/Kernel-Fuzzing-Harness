import unittest

from tripwire.model_lock import validate_model_lock


CONFIG = {
    "runtime": "ollama", "runtime_version": "0.40.7",
    "runtime_linux_amd64_asset": "ollama-linux-amd64.tar.zst",
    "runtime_linux_amd64_sha256": "a" * 64, "model": "qwen3:8b-q4_K_M",
}
LOCK = {
    "runtime": "ollama", "runtime_version": "0.40.7",
    "runtime_asset": "ollama-linux-amd64.tar.zst",
    "runtime_archive_sha256": "a" * 64, "model_tag": "qwen3:8b-q4_K_M",
    "manifest_sha256": "b" * 64, "manifest_layers": ["sha256:" + "c" * 64],
}


class ModelLockTests(unittest.TestCase):
    def test_accepts_matching_archive_model_and_manifest_pin(self):
        self.assertEqual(validate_model_lock(CONFIG, LOCK), LOCK)

    def test_rejects_model_or_runtime_drift(self):
        changed = dict(LOCK, model_tag="qwen3:14b")
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_model_lock(CONFIG, changed)

    def test_rejects_archive_asset_drift(self):
        changed = dict(LOCK, runtime_asset="ollama-linux-amd64.tgz")
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_model_lock(CONFIG, changed)

    def test_rejects_missing_or_malformed_manifest_digest(self):
        changed = dict(LOCK, manifest_sha256="latest")
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            validate_model_lock(CONFIG, changed)


if __name__ == "__main__":
    unittest.main()
