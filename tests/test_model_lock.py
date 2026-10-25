import unittest

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from tripwire.model_lock import (
    cached_model_is_complete,
    model_lock_path,
    validate_model_lock,
)


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
    def test_cached_model_requires_matching_manifest_and_all_blobs(self):
        layer = "sha256:" + "d" * 64
        manifest = {"layers": [{"digest": layer}]}
        manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
        lock = dict(
            LOCK,
            manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            manifest_layers=[layer],
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(manifest_bytes)
            blobs = root / "blobs"
            blobs.mkdir()
            (blobs / ("sha256-" + layer.removeprefix("sha256:"))).write_bytes(b"model")

            self.assertTrue(cached_model_is_complete(manifest_path, root, lock))

            (blobs / ("sha256-" + layer.removeprefix("sha256:"))).unlink()
            self.assertFalse(cached_model_is_complete(manifest_path, root, lock))

    def test_cached_model_rejects_manifest_digest_drift(self):
        manifest_bytes = b'{"layers":[]}'
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(manifest_bytes)
            self.assertFalse(cached_model_is_complete(manifest_path, root, LOCK))

    def test_model_lock_path_matches_profile_name(self):
        self.assertEqual(
            model_lock_path(Path("config/model.json")),
            Path("config/model.lock.json"),
        )
        self.assertEqual(
            model_lock_path(Path("config/model.low-memory.json")),
            Path("config/model.low-memory.lock.json"),
        )

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
