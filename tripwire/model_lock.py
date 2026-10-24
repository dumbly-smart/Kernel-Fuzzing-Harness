"""Validate the exact local runtime archive and model manifest lock."""

from __future__ import annotations

import re
from typing import Any


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LAYER_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


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
