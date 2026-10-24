#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]] || ! systemd-detect-virt --quiet; then
    echo 'ERROR: agent account setup requires root inside a disposable VM' >&2
    exit 1
fi
if ! getent passwd tripwire-agent >/dev/null; then
    useradd --system --home-dir /nonexistent --no-create-home \
        --shell /usr/sbin/nologin tripwire-agent
fi
if [[ $(id -u tripwire-agent) == 0 ]] || \
        id -nG tripwire-agent | tr ' ' '\n' | grep -qx sudo; then
    echo 'ERROR: tripwire-agent must remain an unprivileged non-sudo account' >&2
    exit 1
fi
echo 'tripwire-agent account is unprivileged and has no sudo group'
