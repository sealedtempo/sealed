# Sealed dstack OS image

The guest OS every Sealed deployment boots on Google Cloud Intel TDX (C3/C4
confidential VMs). It is upstream [dstack](https://github.com/Dstack-TEE/dstack)
0.6.1 (Apache-2.0, D-015) built with upstream's own mkosi backend, with the
NVIDIA userspace and ZFS removed and ext4 as the only data-disk filesystem
(D-016). Two variants are built from the same source:

| Variant | Image name | mkosi profiles | Registered as |
|---|---|---|---|
| production | `sealed-dstack-os` | `prod` | `isDebug = false` |
| debug | `sealed-dstack-os-debug` | `prod,sealed-debug` | `isDebug = true` |

Both inherit upstream's production profile: no getty, no `login`, no debug
shell, no `systemd-logind`, no SSH daemon, no TEE simulator, and the serial
console is output only (`console=ttyS0`, boot progress and errors only). The
kernel has no magic SysRq key (`CONFIG_MAGIC_SYSRQ=n`), and the overlay also
sets `kernel.sysrq = 0`, so a serial BREAK from the host cannot reboot, crash
or dump the guest; `check_image.py` fails the build if SysRq could be on. The
debug variant adds one thing: `sealed-logship`, which exports container logs to
the customer project's Cloud Logging (spec 5.8). The key broker never releases
production secrets to a debug image, and acceptance tests run on production.

## Layout

| Path | What |
|---|---|
| `upstream.env` | Pins: upstream repo and commit, Sealed version, image names, fixed commit identity and time |
| `patches/` | Seven `git am` patches on the upstream commit, documented line by line in `patches/README.md` |
| `overlay/` | New files added to the upstream tree in one commit: the `kernel.sysrq = 0` sysctl file, the `sealed-debug` profile and the `sealed-logship` component |
| `logship/` | `sealed-logship` (Go, standard library only), copied into the tree as `os/sealed/logship` |
| `source.lock` | The resulting patched commit and tree; CI fails when it drifts |
| `build.sh` | Prepare, lock, lint, build and package |
| `check_image.py` | License and attack-surface check of the built disk (fails on NVIDIA, ZFS or CDDL content, a login surface, or SysRq left on) |
| `rust_inventory.py` | License inventory of the Rust crates compiled into the guest |
| `license-exceptions.json` | Waivers for `check_image.py`, each tied to a decision id. Empty |
| `tools/osimage/` | Go helper: Authenticode, image identity, measurement compose, quote verification, catalog JSON |
| `import-and-measure.sh` | Imports an image into a GCP project and records MRTD and RTMR0-2 per machine type (operator only) |
| `LICENSES.md` | License inventory of the image |
| `measurements/` | Catalog files written by `import-and-measure.sh` (created on first use) |

## Build

CI (`.github/workflows/os-image.yml`) builds both variants on `ubuntu-24.04`
for every `workflow_dispatch` and `os-image-v*` tag, and publishes the assets
on the tag. Pull requests that touch this directory run the static checks only
(Go and Python tests, shellcheck, actionlint, patch application against
`source.lock`, upstream's static contract on the patched tree).

To reproduce a build, on x86-64 Linux as root (mkosi needs loop devices,
device-mapper and mounts) with the mkosi host dependencies installed:

```bash
d=runtime/images/dstack-os
go build -o /tmp/osimage ./$d/tools/osimage
$d/build.sh prepare /tmp/dstack-src          # upstream 7f143148 + patches + overlay
$d/build.sh check-lock /tmp/dstack-src       # must print the commit in source.lock
. /tmp/dstack-src/os/mkosi/versions.env      # pip install "mkosi @ git+https://github.com/systemd/mkosi.git@$MKOSI_REVISION"
sudo env PATH="$PATH" OSIMAGE=/tmp/osimage $d/build.sh image prod /tmp/dstack-src /tmp/build /tmp/out
```

Then compare `/tmp/out/*.sha256` with the release. The build takes 30 to 45
minutes cold on 4 vCPUs.

### Reproducibility model

- Upstream pins every network input of the build (kernel, Rust and Go
  toolchains, the Debian snapshot `20260721T000000Z`, mkosi itself, every
  component source by commit or sha256), compiles inside mkosi's build overlay,
  and checks byte-identical rebuilds with `build.sh repro-check`.
- `build.sh prepare` adds our changes as commits with a fixed author,
  committer and date (`upstream.env`) and with the caller's git configuration
  ignored, so the patched commit is the same on every machine (it is pinned in
  `source.lock`). That commit is the `git_revision` in `metadata.json`, which is
  inside `os_image_hash`, and its date is `SOURCE_DATE_EPOCH`.
- `package` writes the GCE tarball with GNU tar in oldgnu format, sorted, owner
  0, mtime `SOURCE_DATE_EPOCH`, no sparse detection, and `gzip -n`, so the
  tarball is a pure function of `disk.raw`.

### Outputs (release assets, per variant)

| File | Content |
|---|---|
| `<name>-<version>-gce.tar.gz` | GCE import tarball: exactly one member, `disk.raw` (GPT: 256 MiB ESP with the UKI as `EFI/BOOT/BOOTX64.EFI`, then the squashfs + dm-verity rootfs) |
| `<name>-<version>-identity.tar.gz` | `image-identity.json` plus upstream's `digest.txt`, `sha256sum.txt`, `metadata.json`, `auth_hash.txt` and `measurement.*.cbor` |
| `<name>-<version>-identity.json` | The same `image-identity.json`: `os_image_hash`, UKI Authenticode (sha256 = dstack's `gcp_uki_auth`, sha384 for the TDX RTMR1 event), tarball sha256, source commit and tree, the `vm_config` string for `.sys-config.json` |
| `<name>-<version>-license-inventory.json` | Every Debian package with its version, source package, section and DEP-5 licenses; kernel module license counts; check results |
| `<name>-<version>-rust-crates.json` | The Rust crates compiled into the guest with their license expressions |
| `<name>-<version>-hashes.txt`, `<name>-<version>.sha256` | `os_image_hash`, `gcp_uki_auth`, UKI sha384 Authenticode, `disk.raw` sha256 and the sha256 of every asset |

## Measure and register

On Google Cloud the firmware is Google's, so dstack's `dstack-mr` cannot
compute MRTD or RTMR0 and nobody can compute them from the image alone. They
are recorded from first boots and marked trust on first use (spec 5.1,
THREAT_MODEL). The operator runs, with `gcloud` signed in to a project that has
TDX quota:

```bash
runtime/images/dstack-os/import-and-measure.sh \
  --project P --zone us-central1-a --bucket gs://P-sealed-images \
  --tarball sealed-dstack-os-0.6.1-s2-gce.tar.gz \
  --identity sealed-dstack-os-0.6.1-s2-identity.tar.gz \
  --machine-types c3-standard-8,c3-standard-4 --boots 2 \
  --release-base https://github.com/<owner>/<repo>/releases/download
```

It checks the tarball sha256 against the identity, imports the image
(`UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC`), and boots it once per machine type and
boot, one VM at a time, with no service account, no scopes, no external IP,
project SSH keys blocked and OS Login off. Each VM gets a data disk with the
`dstack-data` partition and a `DSTACKSHR` disk whose `app-compose.json` uses the
`bash` runner: it asks the guest agent for a quote over a fresh 64-byte nonce
and prints the quote and the RTMR0-2 event log to the serial console. No
containers, network or secrets are involved. `osimage measure` then:

- verifies the quote against Intel PCS collateral (any TCB status but
  Revoked is recorded, the status is kept with the record),
- requires `report_data` to equal the nonce and the TD attributes of a
  production TD (no DEBUG, not migratable),
- replays RTMR0-2 from the event log and looks for the UKI's SHA-384
  Authenticode digest among the RTMR1 boot applications (both recorded as
  checks; a mismatch is a warning because the GCP event log format is not yet
  confirmed on a real boot).

`osimage image-json` requires identical MRTD and RTMR0-2 across the boots of a
machine type, groups machine types with identical measurements (PlatformRegistry
keeps images unique by `measurementsHash`, CR-5), and writes
`measurements/<name>-<version>.json` in the `CATALOG_FILE` format of
`contracts/script/RegisterCatalog.s.sol`: `name`, `version` (for example
`0.6.1-s2+c3-standard-4.c3-standard-8`), `mrtd`, `rtmr0` to `rtmr2`,
`isDebug`, `sourceURI` (the release URL with `#sha256=` of the tarball) and
`imageId = keccak256(abi.encode(name, version, measurementsHash))`. Registering
it onchain (`addImage` from OWNER) is a separate operator step.

`--dry-run` prints every gcloud command without running it. Raw quotes, event
logs and the Intel collateral used are kept in the work directory, so a
measurement can be re-verified offline (`osimage measure -offline -at ...`).

## Debug variant and Cloud Logging

`sealed-logship` follows every running container through the Docker API (so
the composer's `local` log driver for debug stacks works) and writes lines to
`projects/<project>/logs/sealed-debug-containers` with `entries:write`, under
the `gce_instance` resource, with labels for container, compose service and
project, image and stream. Its token comes from the metadata server, so a
debug VM must be created with a service account that has
`roles/logging.logWriter` and the `logging.write` scope. Production VMs keep
no service account (spec 5.9). Without one, the exporter waits and says why on
the serial console. Lines are batched (2 s or 500 lines), retried with backoff,
and bounded (20,000 lines); dropped lines are counted and reported in Cloud
Logging once writes work again.

## Changing the patch set

1. `build.sh prepare /tmp/src`, edit in `/tmp/src`, commit there.
2. `git -C /tmp/src format-patch --no-signature --zero-commit -o patches <upstream>..HEAD~1`
   (the last commit is the overlay; keep overlay files in `overlay/`).
3. Document every changed line in `patches/README.md`.
4. Bump `SEALED_OS_VERSION` in `upstream.env`, run `build.sh lock`, commit
   `source.lock`.

Every image built from a new patch set has a new `os_image_hash` and new
RTMR1/RTMR2, so it must be measured and registered again.
