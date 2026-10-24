# Phase 0 VM cloud-init seed transport

## Problem

The runner originally used NoCloudNet over QEMU's user-mode network. After a
Phase 3 guest enabled deny-all UFW, a later boot could not fetch cloud-init
user-data, so its `runcmd` never got the chance to reset UFW. That also blocked
the repository archive needed by Phase 5 through Phase 7. This was confirmed
by guest serial logs with no HTTP request for `repo.tar`.

## Design

The runner now writes `user-data` and a unique `meta-data` instance ID into a
small ISO9660 image labelled `CIDATA`, attaches it read-only as a virtual CD,
and selects the NoCloud datasource through SMBIOS. Cloud-init therefore reads
its seed locally. The `runcmd` resets UFW and only then fetches `repo.tar` from
the host's loopback server through QEMU's private user network. The existing
egress policy remains active across reboot; no broad network exception is
needed.

The ISO writer uses only Python's standard library because the launcher must
not install host packages. It emits the two ASCII NoCloud files, a primary
volume descriptor, path tables and a root directory. The image is padded to
300 2048-byte sectors: smaller generated images were recognized by label but
rejected by cloud-init, and libarchive listed no directory entries; at 300
sectors it listed both seed files. QEMU and cloud-init versions remain recorded
in the VM provenance and guest environment lock.

Cloud-init's documented NoCloud seed formats require `user-data` and
`meta-data` on a filesystem labelled `cidata` or `CIDATA`; see the [NoCloud
datasource documentation](https://cloudinit.readthedocs.io/en/latest/reference/datasources/nocloud.html).
QEMU documents virtual disk and CD media attachment in its [system
documentation](https://www.qemu.org/docs/master/system/qemu-manpage.html).

## Regression acceptance — 2026-10-25

Booted a fresh overlay from the previously model-installed
`guest-phase3-1024.qcow2` disk, whose UFW rules had prevented cloud-init network
bootstrap. Cloud-init reported
`DataSourceNoCloud [seed=dmi,/dev/sr0][dsmode=local]`. The serial log shows
`ufw --force reset` before the successful `GET /repo.tar` response. The guest
then ran the existing acceptance path and reported 125 tests passing; the VM
powered off with exit status 0. The failing ISO case is covered by
`test_nocloud_seed_iso_has_cidata_label_and_both_required_files`, including the
volume label, primary descriptor, directory records, contents, and minimum
image size.

This validates seed recovery on the locked 1 GiB guest. It does not mean the
Phase 3 corpus completed: that run stopped before corpus execution because the
separate UFW lockdown validator did not confirm its expected state.
