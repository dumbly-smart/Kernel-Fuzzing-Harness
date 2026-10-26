#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
guest_memory_mib=${GUEST_MEMORY_MIB:-8192}
guest_swap_mib=${GUEST_SWAP_MIB:-0}
disk_gib=${GUEST_DISK_GIB:-24}
timeout_seconds=${GUEST_TIMEOUT_SECONDS:-3600}
model_config=${MODEL_CONFIG:-config/model.json}

for tool in python3 qemu-system-x86_64 qemu-img gpg; do
    command -v "$tool" >/dev/null || { echo "ERROR: required launcher tool is missing: $tool" >&2; exit 1; }
done
if [[ ! $guest_memory_mib =~ ^[0-9]+$ ]] || (( guest_memory_mib < 1024 )); then
    echo 'ERROR: GUEST_MEMORY_MIB must be an integer of at least 1024' >&2
    exit 1
fi
if [[ ! $guest_swap_mib =~ ^[0-9]+$ ]] || (( guest_swap_mib > 4096 )); then
    echo 'ERROR: GUEST_SWAP_MIB must be an integer between 0 and 4096' >&2
    exit 1
fi
if [[ ! $disk_gib =~ ^[0-9]+$ ]] || (( disk_gib < 12 )); then
    echo 'ERROR: GUEST_DISK_GIB must be an integer of at least 12' >&2
    exit 1
fi
if [[ ! $timeout_seconds =~ ^[0-9]+$ ]] || (( timeout_seconds < 1 )); then
    echo 'ERROR: GUEST_TIMEOUT_SECONDS must be a positive integer' >&2
    exit 1
fi
if [[ ! -f "$repo_dir/$model_config" ]]; then
    echo "ERROR: model config does not exist: $repo_dir/$model_config" >&2
    exit 1
fi

# A simple headroom guard is deliberately conservative; VM and model memory
# demand can exceed guest RAM because QEMU and host services also need memory.
check_host_headroom() {
    local available_mib required_mib
    available_mib=$(awk '$1 == "MemAvailable:" {print int($2 / 1024)}' /proc/meminfo)
    required_mib=$((guest_memory_mib * 2))
    if (( available_mib < required_mib )); then
        echo "ERROR: refusing VM launch: MemAvailable=${available_mib} MiB, required by local 2x headroom policy=${required_mib} MiB" >&2
        echo 'Increase free host memory or lower GUEST_MEMORY_MIB/MODEL_CONFIG explicitly.' >&2
        exit 1
    fi
}

run_guest() {
    check_host_headroom
    TMPDIR=${TMPDIR:-/dev/shm} python3 "$repo_dir/scripts/run_phase0_vm.py" \
        --memory-mib "$guest_memory_mib" --swap-mib "$guest_swap_mib" \
        --disk-gib "$disk_gib" \
        --timeout-seconds "$timeout_seconds" "$@"
}

echo "Phase 0: provision the pinned disposable Ubuntu guest"
run_guest
echo "Phase 3: build benign corpus with $model_config"
run_guest --base-guest --reuse-provisioned-base --overlay-name guest-phase3.qcow2 \
    --phase3 --phase3-model-config "$model_config"
echo "Phase 5: execute local injection suite"
run_guest --base-disk-name guest-phase3.qcow2 --reuse-provisioned-base \
    --overlay-name guest-phase5.qcow2 --phase5 --phase5-model-config "$model_config"
echo "Phase 6: compare naive and adaptive mimicry"
run_guest --base-disk-name guest-phase3.qcow2 --reuse-provisioned-base \
    --overlay-name guest-phase6.qcow2 --phase6
echo "Phase 7: produce calibrated detector and taxonomy tables"
run_guest --base-disk-name guest-phase5.qcow2 --reuse-provisioned-base \
    --overlay-name guest-phase7.qcow2 --phase7
echo "Reproduction finished; guest artifacts are under $repo_dir/data/vm/"
