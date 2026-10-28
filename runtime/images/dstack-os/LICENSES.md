# License inventory of the Sealed dstack OS image

Covers what is on the published GCE boot disk (`disk.raw`): the EFI System
Partition with the unified kernel image, and the squashfs + dm-verity root
filesystem. Policy: rule 9 of the spec, D-016, D-021 and D-050. The Linux kernel
and the Debian packages are OS system components (D-021): allowed when
OSI-approved or DFSG-free and not on the banned list.

The per-build inventory published with every release is authoritative:
`<name>-<version>-license-inventory.json` (every Debian package with version,
source package, section and DEP-5 `License:` fields, and the license count of
every kernel module) and `<name>-<version>-rust-crates.json` (every Rust crate
compiled into the guest). This file describes what goes into them and what was
removed.

## What is in the image

| Component | Where | License | Source and pin |
|---|---|---|---|
| Linux kernel 6.18.40 and its in-tree modules | UKI `.linux`, `/usr/lib/modules` | GPL-2.0-only (with the Linux syscall note) | kernel.org tarball, sha256 in upstream `os/mkosi/versions.env`; dstack's ten kernel patches (`os/yocto/layers/meta-dstack/recipes-kernel/linux/files/0001`-`0010`, GPL-2.0 as kernel modifications) |
| systemd EFI stub | UKI | LGPL-2.1-or-later | Debian `systemd-boot-efi` |
| initramfs: busybox, veritysetup and its libraries, `init` | UKI `.initrd` | busybox GPL-2.0-only; cryptsetup GPL-2.0-or-later; libraries as in their Debian packages; `init` MIT (meta-dstack `dstack-initscript.bb`) | Debian `busybox-static`, `cryptsetup-bin` |
| Debian trixie base system and the listed packages | rootfs | Debian main only (patch 0003): GPL-2.0, GPL-3.0, LGPL-2.1, LGPL-3.0, MIT, BSD, ISC, Apache-2.0, MPL-2.0 and other DFSG-free licenses per package | Snapshot `20260721T000000Z`. Explicit packages: systemd, systemd-boot, systemd-resolved, dbus, ca-certificates, bash, coreutils, iproute2, iptables, nftables, docker.io, docker-cli, docker-compose, containerd, chrony, wireguard-tools, cryptsetup, dmsetup, tpm2-tools, curl, wget, iputils-ping, dnsutils, traceroute, netcat-openbsd, fdisk, dosfstools, pciutils, usbutils, cpio, jq, fuse3, pigz, rsync, xfsprogs, e2fsprogs, gdisk, parted, busybox-static, cryptsetup-bin, systemd-boot-efi, acpid, numactl, plus their dependencies |
| dstack guest services: `dstack-guest-agent`, `dstack-util`, `dstack-volume` | `/usr/bin` | Apache-2.0 (`LICENSE`, SPDX headers; the Rust workspace manifest says MIT, also allowed) | Built from the patched commit with Rust 1.92.0 and `Cargo.lock --locked`; crates in `-rust-crates.json` |
| dstack guest payload (units, `dstack-prepare.sh`, `app-compose.sh`, configs) | `/usr/bin`, `/usr/lib/systemd`, `/etc` | Apache-2.0 | `os/common/rootfs`, `os/mkosi/mkosi.skeleton` |
| nerdctl 2.3.5, CNI plugins 1.3.0, stargz-snapshotter 0.18.2 | `/usr/bin`, `/usr/lib/cni` | Apache-2.0 | Upstream release binaries, sha256-pinned in `versions.env` |
| Sysbox 0.6.7 (`sysbox-runc`, `sysbox-fs`, `sysbox-mgr`) | `/usr/bin` | Apache-2.0 | Built from source at pinned commits |
| `sealed-logship` (debug variant only) | `/usr/bin` | Apache-2.0; Go standard library BSD-3-Clause | `runtime/images/dstack-os/logship`, built with Go 1.26.2 |

Built during the image build but not shipped on the disk: `dstack-mr` and
`nitro-tpm-pcr-compute` (removed from the tree in `mkosi.finalize` after they
compute the measurement files), the kernel build tree (`kernel-devel`, a
separate artifact we do not publish), and the TDX and SEV OVMF firmware
(bare-metal only; Google Cloud boots its own firmware).

## What was removed (D-016)

| Removed | License | How |
|---|---|---|
| NVIDIA driver 595.91.07 userspace (`libcuda`, `libnvidia-*`, `nvidia-smi`, `nvidia-persistenced`, ...), GSP firmware, Fabric Manager, NSCQ | NVIDIA proprietary | component `nvidia` not built (patch 0001) |
| NVIDIA open GPU kernel modules (`nvidia.ko`, `nvidia-uvm.ko`, `nvidia-modeset.ko`, `nvidia-drm.ko`, `nvidia-peermem.ko`) | MIT/GPL-2.0 | same component |
| `nvattest` and `libnvat` (NVIDIA attestation SDK) and its OPA policy | Apache-2.0 | component `nvattest` not built (0001); `libxmlsec1` runtime packages dropped (0002) |
| libnvidia-container and the NVIDIA Container Toolkit | Apache-2.0 | removed from `container-stack` (0001); `nvidia` Docker runtime and nvidia units removed (0002) |
| OpenZFS 2.4.0 userspace (`zfs`, `zpool`, `zed`, `libzfs`, ...) and `zfs.ko`/`spl` | CDDL-1.0 | component `zfs` not built (0001); `storage_fs` is ext4 only (0005) |
| Anything from Debian `contrib` and `non-free-firmware` | various | `Repositories=main` (0003) |

## Checks that fail the build

`check_image.py` runs in CI on the exact `disk.raw` being published, after
extracting the rootfs with `unsquashfs`:

- no path anywhere matching NVIDIA or ZFS names (`nvidia`, `libcuda`,
  `nvcuvid`, `nvattest`, `libnvat`, `fabricmanager`, `nvswitch`, `nscq`, `zfs`,
  `zpool`, `zdb`, `zed`, `libnvpair`, `libuutil`, `spl.ko`). In-tree GPL kernel
  modules whose names contain `nvidia` (for example `i2c-nvidia-gpu`) are
  allowed and checked by metadata instead; the out-of-tree driver module names
  are always rejected;
- every kernel module is in-tree (`intree=Y`) and declares a license the kernel
  treats as GPL-compatible (`GPL`, `GPL v2`, `GPL and additional rights`,
  `Dual BSD/GPL`, `Dual MIT/GPL`, `Dual MPL/GPL`);
- no ELF file has a `DT_NEEDED` entry on an NVIDIA or ZFS library;
- no non-ELF file contains `CDDL` or `Common Development and Distribution
  License`;
- every Debian package is from `main`, has a copyright file, declares no banned
  license (CDDL, SSPL, BUSL, Elastic, Commons Clause, proprietary, NVIDIA,
  non-free) and its copyright file does not mention CDDL;
- the ESP contains only `EFI/BOOT/BOOTX64.EFI`;
- no login, shell, debugger or SSH component is present (`sshd`, `login`,
  `agetty`, getty units and generator, `debug-shell.service`, `systemd-logind`,
  the TEE simulator, `swtpm`, `gdb`, `strace`, `tcpdump`), in both variants.

Inside the build, upstream's `check-parity.py` additionally refuses the main
NVIDIA and ZFS paths (patch 0004) before the image is assembled.
`rust_inventory.py` fails on a crate with a banned license or with no license
information and lists every crate whose license expression is outside the
allowlist for a decision. Waivers go in `license-exceptions.json` with a
decision id; it is empty.
