# Patch set on dstack v0.6.1

Base: `Dstack-TEE/dstack` tag `v0.6.1`, commit
`7f143148cc49f4a09799958835d310e050137cb3` (Apache-2.0). `build.sh prepare`
applies these with `git am --no-3way` (no fuzz, no merge), in order, then adds
`overlay/` as one more commit. Paths below are relative to the upstream tree.
Every changed line is listed. Upstream's own static contract
(`os/mkosi/tests/acceptance.sh`, run by `build.sh lint`) passes on the result
unchanged, because the NVIDIA, nvattest and ZFS component definitions stay in
the tree and are only taken out of the build list.

## 0001 mkosi: do not build the NVIDIA, nvattest and ZFS components

`os/mkosi/scripts/build-components.sh`

| Line | Change | Why |
|---|---|---|
| `components=(` list | removed `nvattest`, `nvidia`, `zfs` | These three components produce the NVIDIA driver 595.91.07 userspace, firmware, Fabric Manager and NSCQ (NVIDIA proprietary license), the NVIDIA open kernel modules, NVIDIA's attestation CLI `nvattest`, and OpenZFS 2.4.0 (CDDL-1.0, userspace and `zfs.ko`). None may ship (rule 9, D-016). The remaining order (`dstack-rust image-tools container-stack sysbox kernel ovmf`) is upstream's order without the three |
| 3 comment lines above the list | added | States the above in the file |

`os/mkosi/components/container-stack/container-stack-build.sh`

| Line | Change | Why |
|---|---|---|
| upstream lines 30-66 | removed | Built and installed `libnvidia-container` 1.18.1 (`nvidia-container-cli`, `libnvidia-container.so.1`, `libnvidia-container-go.so.1`) and the NVIDIA Container Toolkit (`nvidia-container-runtime*`, `nvidia-ctk`, `nvidia-cdi-hook`, `/etc/nvidia-container-runtime/config.toml`). They are Apache-2.0 but are NVIDIA userspace that only serves the removed driver. The `export CFLAGS/LDFLAGS/CGO_CFLAGS/GOFLAGS` lines in that block only fed these two builds; nerdctl, CNI plugins and stargz-snapshotter below are pinned release binaries and are unaffected |
| 2 comment lines | added | Marks the removal |

The now unused `checkout()` helper in that script is left in place (one less
changed line).

## 0002 mkosi: drop the NVIDIA runtime, units and nvattest libraries

`os/mkosi/mkosi.skeleton/etc/docker/daemon.json`

| Line | Change | Why |
|---|---|---|
| `"nvidia": {"args": [], "path": "nvidia-container-runtime"},` | removed | The runtime binary no longer exists. `sysbox-runc` stays |

`os/mkosi/mkosi.skeleton/usr/lib/systemd/system-preset/80-dstack.preset`

| Line | Change | Why |
|---|---|---|
| `enable nvidia-module-options.service` | removed | Unit no longer installed |
| `enable nvidia-persistenced.service` | removed | Unit no longer installed |
| `enable nvidia-fabricmanager.service` | removed | Unit no longer installed |

`os/mkosi/mkosi.conf`

| Line | Change | Why |
|---|---|---|
| `libxmlsec1t64-openssl`, `libxmlsec1t64` in `Packages=` | removed | Only `nvattest` linked against them (upstream's own comment says so) |
| the 5-line comment explaining them | replaced by a 2-line comment | Explains the removal |

## 0003 mkosi: install packages from Debian main only

`os/mkosi/mkosi.conf`

| Line | Change | Why |
|---|---|---|
| `Repositories=main,contrib,non-free-firmware` | now `Repositories=main` | No runtime or build package comes from `contrib` or `non-free-firmware`; removing them makes it impossible for one to. The Debian part of the image is then DFSG-free by construction, which is what D-021 treats as OS system components |
| 2 comment lines | added | States the above |

## 0004 mkosi: parity without NVIDIA and ZFS, and forbid their paths

`os/mkosi/parity.json` (read by `tests/check-parity.py` in `mkosi.finalize`
on every build, before release assembly)

| Entry | Change | Why |
|---|---|---|
| `required_rootfs_paths."zfs-2.4.0"` (4 paths) | removed | ZFS is not built |
| `required_rootfs_paths."nvidia-595.91.07"` (10 paths) | removed | NVIDIA is not built |
| `required_rootfs_paths."nvidia-container"` (6 paths) | removed | Not built (0001) |
| `required_rootfs_paths."nvattest-2026.06.09"` (4 paths) | removed | Not built |
| `required_kernel_globs` `nvidia` (5 modules) and `zfs` (1 module) | removed, the object is now `{}` | Not built |
| `required_rootfs_globs."nvidia-firmware"`, `."nvidia-libraries"` | removed | Not built. `cni-plugins` stays |
| `prod_forbidden_paths` | added `usr/bin/nvidia-smi`, `usr/bin/nvidia-persistenced`, `usr/bin/nvidia-container-cli`, `usr/bin/nvattest`, `usr/lib/firmware/nvidia`, `usr/lib/x86_64-linux-gnu/libcuda.so.1`, `usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1`, `usr/sbin/zfs`, `usr/sbin/zpool` | If any of these ever comes back, the build fails inside mkosi, before an image exists. Both Sealed variants are built with the prod flavor, so the list applies to both |
| `required_ldconfig_entries` | now `[]` | All three entries were NVIDIA libraries |
| `runtime_link_paths` | now `[]` | All four entries were NVIDIA or ZFS binaries |

## 0005 dstack-util: ext4 is the only data-disk filesystem

`dstack/dstack-util/src/system_setup.rs`

| Line | Change | Why |
|---|---|---|
| `enum FsType` | `#[default]` moved from `Zfs` to `Ext4`, comment on `Zfs` | An omitted `storage_fs` used to mean ZFS, which this image cannot mount |
| `FromStr for FsType`, `"zfs"` arm | now `bail!("Invalid filesystem type: zfs is not supported by this image, use ext4")` | A compose (or kernel command line) that asks for ZFS fails at boot with a clear error instead of failing later on a missing `zpool` |
| `FromStr`, fallback arm | message now says `supported types: ext4` | Accurate message |
| `parse_dstack_options`, `storage_fs: FsType::Zfs` | now `FsType::Ext4` | Same default as the enum |

The ZFS code paths stay but are unreachable, since nothing constructs
`FsType::Zfs` any more. The measured `storage-fs` runtime event (RTMR3) is
therefore always `ext4`. The Sealed composer writes `"storage_fs": "ext4"`
explicitly anyway.

## 0006 mkosi: save the package list and copyright files for the license inventory

`os/mkosi/mkosi.postinst`, 19 lines added after `B=${BUILDROOT:?}`

| Lines | Why |
|---|---|
| comment (6 lines) | Explains the hook |
| `inventory="${OUTPUTDIR:?}/dstack-sealed-inventory"`, `rm -rf`, `mkdir -p` | A fresh directory in mkosi's staging output, outside the image. The `dstack-` prefix makes upstream's `mkosi.clean` delete it with the other outputs |
| `dpkg-query --admindir="$B/var/lib/dpkg" -W -f=... \| LC_ALL=C sort > packages.tsv` | Binary package, version, source package and version, section and architecture of every installed package, sorted. This must run in postinst: `CleanPackageMetadata=yes` and the prod profile's `RemoveFiles=/var/lib/dpkg` delete the database afterwards |
| `for copyright in "$B"/usr/share/doc/*/copyright` loop | Copies each package's copyright file (kept by mkosi even with `WithDocs=no`) before the prod profile's `RemoveFiles=/usr/share/doc` deletes them |

Nothing is written into the image, so the rootfs and every measurement are the
same as without this hook.

## 0007 mkosi: build the sealed-logship component in the debug variant only

`os/mkosi/scripts/build-components.sh`, 6 lines after the component list

| Lines | Why |
|---|---|
| 3 comment lines | Explain the condition |
| `if [[ ${SEALED_IMAGE_VARIANT:-prod} == debug ]]; then components+=(sealed-logship); fi` | The `sealed-debug` profile (overlay) sets `SEALED_IMAGE_VARIANT=debug`; nothing else does, so the production variant never builds or ships the exporter |

## 0008 mkosi: ship the Go and project license texts for sysbox and the container stack

`os/mkosi/components/sysbox/sysbox-build.sh`, 21 lines added before the final
`find "$STAGE" ... touch`

| Lines | Why |
|---|---|
| comment (8 lines) | Explains why the texts are installed under `/usr/share/licenses` |
| `goroot=$(go env GOROOT)`, two `sha256sum -c` checks, two `install -Dm0644 "$goroot/..."` | Go's `LICENSE` and `PATENTS` (BSD-3-Clause, the same sha256 as `runtime/envexec` and `sealed-logship`) into `/usr/share/licenses/sysbox/go`. The binaries are Go programs, so they carry the standard library notice |
| `for mod in sysbox-runc sysbox-fs sysbox-mgr` loop (sha256 check, `install -Dm0644 "$B/$mod/LICENSE"`) | Each module's Apache-2.0 `LICENSE` from its pinned source checkout into `/usr/share/licenses/sysbox/<mod>-LICENSE` (git blobs `sysbox-runc` `385b1fd2`, `sysbox-fs`/`sysbox-mgr` `c6087d5b`) |

`os/mkosi/components/container-stack/container-stack-build.sh`, 23 lines added
before the final `find "$STAGE" ... touch`

| Lines | Why |
|---|---|
| comment (8 lines) | Explains the pinned texts (the release tarballs carry no license file) |
| `goroot=$(go env GOROOT)`, two `sha256sum -c` checks, two `install -Dm0644 "$goroot/..."` | Go's `LICENSE` and `PATENTS` into `/usr/share/licenses/container-stack/go` |
| `LICENSES="$SELF/components/container-stack/licenses"`, `for proj in nerdctl cni-plugins stargz-snapshotter` loop (sha256 check, `install -Dm0644 "$LICENSES/$proj-LICENSE"`) | Each project's Apache-2.0 `LICENSE`, pinned in the overlay, into `/usr/share/licenses/container-stack/<proj>-LICENSE` (git blobs nerdctl/stargz `d6456956`, CNI `8dada3ed`) |

Neither change touches a measured removal or a required path, so upstream's
static contract and `check-parity.py` are unaffected. `check_image.py` requires
all ten paths on both the prod and the debug disk.

## Overlay commit (`overlay/`, not a patch)

New files, added verbatim in one commit with fixed metadata:

| File | Purpose |
|---|---|
| `os/mkosi/mkosi.profiles/sealed-debug/mkosi.conf` | `[Build] Environment=SEALED_IMAGE_VARIANT=debug`. Always used as `--profile=prod,sealed-debug`, so it inherits every production removal and adds nothing else (`build.sh lint` rejects `Packages=`, `RemoveFiles=` or `ExtraTrees=` in it) |
| `os/mkosi/components/sealed-logship/sealed-logship.sh` | Component descriptor in upstream's component framework (cache key inputs for development builds, build entry point) |
| `os/mkosi/components/sealed-logship/sealed-logship-build.sh` | `go build -trimpath -buildvcs=false -ldflags='-s -w -buildid='` with `CGO_ENABLED=0`, `GOPROXY=off` and upstream's pinned Go 1.26.2 (`GOTOOLCHAIN=local`), then installs the unit and preset |
| `os/mkosi/components/sealed-logship/sealed-logship.service` | Runs the exporter after Docker, restart always, systemd sandboxing (read-only system, no capabilities, no new privileges), status to the serial console |
| `os/mkosi/components/sealed-logship/82-dstack-sealed-debug.preset` | `enable sealed-logship.service`. The name contains `dstack` because upstream's `mkosi.postinst` deletes every other preset file |
| `os/sealed/logship/*.go`, `go.mod` | Copied by `build.sh prepare` from `runtime/images/dstack-os/logship` (tests excluded), module `sealed.dev/logship`, `go 1.26`, no requirements |
| `os/mkosi/components/container-stack/licenses/{nerdctl,cni-plugins,stargz-snapshotter}-LICENSE` | The three projects' Apache-2.0 texts at the pinned release tags (the binary tarballs ship no license file). Patch 0008 sha256-checks and installs them. Kept byte for byte by `runtime/images/dstack-os/.gitattributes` (`-text`) |
