"""Validate the exact local runtime archive and model manifest lock."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LAYER_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def model_lock_path(config_path: Path) -> Path:
    """Keep each alternative model profile paired with its own digest lock."""
    config_path = Path(config_path)
    if config_path.suffix != ".json":
        raise ValueError("model config path must end in .json")
    return config_path.with_name(f"{config_path.stem}.lock.json")


def validate_model_lock(config: dict[str, Any], lock: Any) -> dict[str, Any]:
    if not isinstance(lock, dict):
        raise ValueError("model lock must be a JSON object")
    expected = {
        "runtime": config.get("runtime"),
        "runtime_version": config.get("runtime_version"),
        "runtime_asset": config.get("runtime_linux_amd64_asset"),
        "runtime_archive_sha256": config.get("runtime_linux_amd64_sha256"),
        "model_tag": config.get("model"),
    }
    if any(lock.get(key) != value for key, value in expected.items()):
        raise ValueError("model lock does not match configured runtime or model")
    if not isinstance(lock.get("manifest_sha256"), str) or not _SHA256.fullmatch(
            lock["manifest_sha256"]):
        raise ValueError("model lock manifest digest must be a SHA256")
    layers = lock.get("manifest_layers")
    if (not isinstance(layers, list) or not layers or
            any(not isinstance(layer, str) or not _LAYER_DIGEST.fullmatch(layer)
                for layer in layers)):
        raise ValueError("model lock must contain SHA256 manifest layer digests")
    return lock


def cached_model_is_complete(manifest_path: Path, models_directory: Path,
                             lock: dict[str, Any]) -> bool:
    """Check pinned manifest bytes and every referenced Ollama blob before reuse."""
    manifest_path = Path(manifest_path)
    models_directory = Path(models_directory)
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(manifest, dict):
        return False
    layers = manifest.get("layers")
    if not isinstance(layers, list):
        return False
    digests = [layer.get("digest") if isinstance(layer, dict) else None
               for layer in layers]
    if (hashlib.sha256(manifest_bytes).hexdigest() != lock.get("manifest_sha256") or
            digests != lock.get("manifest_layers")):
        return False
    for digest in digests:
        if not isinstance(digest, str) or not _LAYER_DIGEST.fullmatch(digest):
            return False
        blob = models_directory / "blobs" / f"sha256-{digest.removeprefix('sha256:')}"
        try:
            if blob.is_symlink() or not blob.is_file() or blob.stat().st_size == 0:
                return False
            blob_hash = hashlib.sha256()
            with blob.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    blob_hash.update(chunk)
        except OSError:
            return False
        if blob_hash.hexdigest() != digest.removeprefix("sha256:"):
            return False
    return bool(digests)
