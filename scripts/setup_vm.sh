#!/usr/bin/env bash
# Run only inside the disposable guest. No host provisioning is performed.
set -euo pipefail
trap 'printf "ERROR: setup_vm.sh line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$?" >&2' ERR
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ${1:-} != --disposable-guest || $# != 1 ]]; then
    echo 'Usage: sudo bash scripts/setup_vm.sh --disposable-guest' >&2
    echo 'The flag attests this is a throwaway VM/container you control.' >&2
    exit 2
fi
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'ERROR: Ubuntu 24.04 required' >&2; exit 1; }
[[ $(dpkg --print-architecture) == amd64 ]] || { echo 'ERROR: amd64 required' >&2; exit 1; }
systemd-detect-virt --quiet || { echo 'ERROR: no VM/container detected; refusing package installation' >&2; exit 1; }
[[ $EUID == 0 ]] || { echo 'ERROR: run setup as root inside the guest' >&2; exit 1; }
mapfile -t packages < <(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["packages"]))' "$repo_dir/config/environment.json")
snapshot=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["snapshot"])' "$repo_dir/config/environment.json")
apt_dir=$(mktemp -d)
trap 'rm -rf -- "$apt_dir"' EXIT
chmod 755 "$apt_dir"
mkdir -p "$apt_dir/lists/partial" "$apt_dir/empty"
cat > "$apt_dir/sources.list" <<SOURCES
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/$snapshot/ noble main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/$snapshot/ noble-updates main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/$snapshot/ noble-security main restricted universe multiverse
SOURCES
# Separate sources and indexes prevent PPAs or newer guest indexes changing pins.
apt_options=(-o "Dir::Etc::sourcelist=$apt_dir/sources.list" -o "Dir::Etc::sourceparts=$apt_dir/empty" -o "Dir::State::lists=$apt_dir/lists" -o Acquire::Check-Valid-Until=false)
apt-get "${apt_options[@]}" update
pinned=()
for package in "${packages[@]}"; do
    version=$(apt-cache "${apt_options[@]}" madison "$package" | awk 'NR == 1 {print $3}')
    [[ -n $version && $version != '(none)' ]] || { echo "ERROR: no snapshot candidate for $package" >&2; exit 1; }
    pinned+=("$package=$version")
done
# Exact versions + an immutable archive date; no silent downgrade of a newer guest.
apt-get "${apt_options[@]}" install --yes --no-install-recommends "${pinned[@]}"
expected_kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*-generic' -printf '%f\n' | sort -V | tail -n 1)
[[ -n $expected_kernel ]] || { echo 'ERROR: no generic kernel installed' >&2; exit 1; }
expected_kernel=${expected_kernel#vmlinuz-}
if [[ $(uname -r) != "$expected_kernel" ]]; then
    echo "ERROR: running $(uname -r); installed $expected_kernel. Reboot the VM into that kernel, then rerun setup. Containers must use a matching guest VM kernel." >&2
    exit 1
fi
cd -- "$repo_dir"
python3 scripts/check_env.py --record
make check
