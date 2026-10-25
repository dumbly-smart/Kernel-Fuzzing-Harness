#!/usr/bin/env bash
set -euo pipefail
trap 'printf "ERROR: install_local_model.sh line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$?" >&2' ERR

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
record_lock=0
model_config=config/model.json
while (($#)); do
    case "$1" in
        --record-lock) record_lock=1; shift ;;
        --model-config)
            (($# >= 2)) || { echo 'ERROR: --model-config requires a path' >&2; exit 2; }
            model_config=$2; shift 2 ;;
        *) echo 'Usage: sudo bash scripts/install_local_model.sh [--record-lock] [--model-config config/model.json]' >&2; exit 2 ;;
    esac
done
[[ $model_config == config/*.json && -f "$repo_dir/$model_config" ]] || {
    echo "ERROR: model config must name an existing config/*.json file: $model_config" >&2
    exit 2
}
if [[ ${EUID} -ne 0 ]] || ! systemd-detect-virt --quiet; then
    echo 'ERROR: local model installation requires root inside the disposable VM' >&2
    exit 1
fi
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'ERROR: Ubuntu 24.04 required' >&2; exit 1; }
[[ $(dpkg --print-architecture) == amd64 ]] || { echo 'ERROR: amd64 required' >&2; exit 1; }

mapfile -t model_settings < <(python3 - "$repo_dir/$model_config" <<'PY'
import json
import sys
config = json.load(open(sys.argv[1], encoding="utf-8"))
print(config["runtime_version"])
print(config["runtime_linux_amd64_asset"])
print(config["runtime_linux_amd64_sha256"])
print(config["model"])
PY
)
runtime_version=${model_settings[0]}
archive_asset=${model_settings[1]}
archive_sha256=${model_settings[2]}
model_tag=${model_settings[3]}
[[ $model_tag =~ ^[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+$ && $model_tag != *..* ]] || {
    echo "ERROR: unsupported unsafe Ollama model tag: $model_tag" >&2
    exit 1
}
models_dir=/var/lib/tripwire-ollama
manifest="$models_dir/manifests/registry.ollama.ai/library/${model_tag/:/\/}"
lock_name=$(python3 - "$model_config" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
print(p.with_name(f"{p.stem}.lock.json"))
PY
)
lock_path="$repo_dir/$lock_name"
archive_url="https://github.com/ollama/ollama/releases/download/v${runtime_version}/${archive_asset}"
cache_dir=/var/cache/tripwire
archive="$cache_dir/ollama-linux-amd64-v${runtime_version}.tar.zst"
mkdir -p "$cache_dir"
if [[ ! -f $archive ]]; then
    curl --fail --location --retry 3 --output "$archive.part" "$archive_url"
    mv "$archive.part" "$archive"
fi
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum --check --status || {
    echo "ERROR: Ollama archive SHA256 mismatch for $archive" >&2
    exit 1
}
tar --zstd -xf "$archive" -C /usr/local
install -d -o ubuntu -g ubuntu "$models_dir"
cat > /etc/systemd/system/tripwire-ollama.service <<'UNIT'
[Unit]
Description=Tripwire local-only Ollama model service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
Environment=OLLAMA_HOST=127.0.0.1:11434
Environment=OLLAMA_MODELS=/var/lib/tripwire-ollama
Environment=OLLAMA_NUM_PARALLEL=1
ExecStart=/usr/local/bin/ollama serve
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now tripwire-ollama.service

for _ in $(seq 1 120); do
    if curl --fail --silent http://127.0.0.1:11434/api/version >/dev/null; then break; fi
    sleep 1
done
if ! curl --fail --silent http://127.0.0.1:11434/api/version >/dev/null; then
    journalctl -u tripwire-ollama.service --no-pager -n 80 >&2
    echo 'ERROR: local Ollama service did not become ready on 127.0.0.1:11434' >&2
    exit 1
fi
version_json=$(curl --fail --silent --show-error http://127.0.0.1:11434/api/version)
version=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["version"])' <<< "$version_json")
[[ $version == "$runtime_version" ]] || {
    echo "ERROR: expected Ollama $runtime_version, got: $version" >&2
    exit 1
}
if PYTHONPATH="$repo_dir" python3 - "$repo_dir/$model_config" "$lock_path" "$manifest" "$models_dir" <<'PY'
import json
from pathlib import Path
import sys

from tripwire.model_lock import cached_model_is_complete, validate_model_lock

config_path, lock_path, manifest_path, models_dir = map(Path, sys.argv[1:])
try:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    lock = validate_model_lock(
        config, json.loads(lock_path.read_text(encoding="utf-8")))
except (OSError, json.JSONDecodeError, ValueError):
    raise SystemExit(1)
raise SystemExit(0 if cached_model_is_complete(manifest_path, models_dir, lock) else 1)
PY
then
    echo "Using complete cached Ollama model verified against $lock_path"
else
    sudo -u ubuntu env OLLAMA_HOST=127.0.0.1:11434 /usr/local/bin/ollama pull "$model_tag"
fi

[[ -s $manifest ]] || {
    echo "ERROR: Ollama model manifest missing at $manifest" >&2
    exit 1
}
actual_lock=$(mktemp /var/cache/tripwire/model-lock.XXXXXX.json)
python3 - "$manifest" "$archive_sha256" "$runtime_version" "$archive_asset" "$model_tag" "$actual_lock" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

manifest_path, archive_sha, version, archive_asset, model_tag, output = sys.argv[1:]
manifest_bytes = Path(manifest_path).read_bytes()
manifest = json.loads(manifest_bytes)
lock = {
    "runtime": "ollama",
    "runtime_version": version,
    "runtime_asset": archive_asset,
    "runtime_archive_sha256": archive_sha,
    "model_tag": model_tag,
    "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    "manifest_layers": [layer["digest"] for layer in manifest["layers"]],
}
Path(output).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if (( record_lock )); then
    install -m 0644 "$actual_lock" "$lock_path"
    echo "Recorded local model lock: $lock_path"
elif [[ ! -f $lock_path ]] || ! python3 - "$actual_lock" "$lock_path" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as actual_file:
        actual = json.load(actual_file)
    with open(sys.argv[2], encoding="utf-8") as expected_file:
        expected = json.load(expected_file)
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if actual == expected else 1)
PY
then
    echo "ERROR: installed Ollama/model digest does not match $lock_path; inspect the manifest and update pins deliberately" >&2
    cat "$actual_lock" >&2
    exit 1
fi
rm -f "$actual_lock"
echo "Ollama $runtime_version ready at 127.0.0.1:11434 with $model_tag"
