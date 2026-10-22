# Phase 0: automated disposable VM

The existing host QEMU is used solely to launch a disposable VM. Packages and
BPF compilation run inside that guest. There are no shared filesystems, forwarded
SSH ports, host credentials, or host package installations. A loopback HTTP
server serves only cloud-init seed files and `git archive HEAD`. Results return
via the emulated serial port. The guest shuts down after the check.

## Reproduce

Prerequisites on the development machine: Python >= 3.11, Git, curl, GnuPG,
QEMU with accessible KVM, approximately 6 GiB free disk and 2 GiB guest RAM.
This launcher was prepared with QEMU 11.1.2; the exact observed version and
arguments are saved in `data/vm/provenance.json`. It stops the guest if free
space drops below 2 GiB. It does not install host dependencies.

From the repository root:

```sh
mkdir -p data/vm/gnupg
chmod 700 data/vm/gnupg
curl -fL -o data/vm/SHA256SUMS https://cloud-images.ubuntu.com/releases/noble/release-20260926/SHA256SUMS
curl -fL -o data/vm/SHA256SUMS.gpg https://cloud-images.ubuntu.com/releases/noble/release-20260926/SHA256SUMS.gpg
curl -fL -o data/vm/signing-key.asc 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xD2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'
gpg --homedir data/vm/gnupg --batch --import data/vm/signing-key.asc
curl -fL -C - -o data/vm/ubuntu-24.04-server-cloudimg-amd64.img https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.img
python3 scripts/run_phase0_vm.py
```

Expected image SHA256, from the signed manifest:
`6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2`.
The launcher checks the detached signature against the exact fingerprint
`D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`, then checks the image checksum.
The fingerprint is published in Canonical's image-verification documentation:
https://documentation.ubuntu.com/_/downloads/public-images/en/latest/pdf/
GnuPG's trust warning is expected with a fresh keyring; acceptance depends on
the exact pinned signing fingerprint and valid signature, not local ownertrust.

`data/vm/guest.qcow2` is a disposable overlay backed by the verified image.
The launcher refuses to overwrite an existing overlay. Preserve the entire
`data/vm/` directory for debugging or remove the overlay explicitly for a fresh
run. The cloud-init service handles the generic-kernel reboot, runs setup twice
(idempotency), and runs `make check` and `make test` as the unprivileged Ubuntu
user. Outputs and the environment lock are saved under `data/vm/`; review them
before copying a successful lock into `config/` and committing it.

## Failures observed during preparation

- `graft map`: `✗ no graph — run graft build first`; the MCP project list also
  lacked this repository. Direct reads of the Phase 0 files were used.
- `https://cloud-images.ubuntu.com/ubuntu-cloudimage-keyring.gpg`: HTTP 404.
  The documented Ubuntu keyserver and pinned cloud-image fingerprint were used
  explicitly instead; checksum signature verification succeeded.

Guest acceptance completed successfully; see
[the acceptance log](phase0-guest-acceptance.txt) and
[the exact tested launch provenance](phase0-vm-provenance.json).
The tested run used `nocloud-net`; the subsequent small datasource/vendor-data
launcher fix passed syntax checking and the existing tests but has not had
a second fresh-VM run.
