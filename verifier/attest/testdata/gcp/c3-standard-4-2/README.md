# gcp/c3-standard-4-2: a second, fresh c3-standard-4 TDX VM

The second VM of machine type `c3-standard-4`. The first is the runtime spike in `../` (see `../README.md`).
Captured on 2026-10-28 to find out which registers are per instance. `TestRealGCPMachineTypes`
(`../../../golden_gcp_machines_test.go`) verifies both quotes offline against the collateral in `pcs/` and compares
this VM with the spike and with `../c3-standard-8-1/`.

**The OS image is upstream dstack 0.6.1** (`os_image_hash` `ec43cb8c...`), as in the spike. Per D-016, **never
register these measurements onchain.**

## What was the same as the spike, and what was not

The VM was booted from the same GCE image as the spike. Its shared and data disks were created from the spike's own
disk tarballs, unchanged: byte-identical `app-compose.json`, `.sys-config.json` and `.instance_info` (the same
`instance_id_seed`). So every difference below comes from the VM itself.

| | this VM | spike (`../`) |
|---|---|---|
| Machine | `c3-standard-4` (4 vCPU, 16 GiB), Intel Sapphire Rapids, `us-central1-a`, on-demand | same |
| Physical platform (PPID in the leaf PCK certificate) | `77bad2a988e00c7d0a6b2e0929f4b9f5` | `d7ec7f1ed14462216e5f045650aa29ea` (boot 1), `2968b9c5541454559a172dd9af9a090a` (boot 2) |
| MRTD | `f21e6b48...1731e5d3` | **same** |
| RTMR0 | `4b08605d...aa232662` | **same** |
| RTMR1, RTMR2 | `fea84c84...d96fbcf3`, `961f79aa...a714239c` | **same** |
| measurementsHash | `0xd63f2a83b0334d1a026b7a1af14fe5c8d5628fea1e761e14a900ebd0c19e3c49` | **same** |
| TD_ATTRIBUTES, XFAM | `0000001000000000`, `e702060000000000` | **same** |
| MRSEAM, TEE_TCB_SVN | `ab62561a...d4127f6b`, `0f010a00000000000000000000000000` | **same** |
| MRCONFIGID, MROWNERCONFIG, MRSIGNERSEAM | all zero | same |
| MROWNER | `78b43b6b49e746766f288a01f803ab3788133edf09f91d99e89f4271ab2bf276337692853fbd1ac79b6a29ebc7f61aa5` | **differs** (`1b203465...28fd8098`) |
| instance-id event | `cf68f16c13fed736080213a5faba0d90faafe4c6` | **differs** (`8a7611f1...e9137908`) although the seed is the same |
| RTMR3 | `a6c2c4f1ada2fc861b2912d1a4f74f1a2ae91ad73be0475494aa32ebe85b668abf17b3c5da398ab444f6e816a2edc065` | differs, only through instance-id |

So MRTD and RTMR0 were the same on three physical platforms (three PPIDs) for this machine type: they are not per
host or per instance. MROWNER and instance-id are per instance. The spike's MROWNER did not change across its
stop and start, which moved it to another host, so MROWNER belongs to the instance, not to the host.

instance-id is `sha256(instance_id_seed || app_id || sha256(vTPM AK public area))[0..20]` (docs/notes/dstack.md in
the platform repo). The same seed on a new VM gives a new instance-id, because the vTPM AK is new.

`tools/predict_rtmr12.py <disk.raw> captures/boot1-getquote1.json` (in `../tools/`) rebuilds every RTMR1 and RTMR2
event from the release `disk.raw` and matches this quote. Its output is `predicted-rtmr12.json`.

## Files

| file | what it is |
|---|---|
| `expected.json` | the values the test asserts: capture times, lengths, TCB result, quoteHash of `quote.dat`, all registers, measurementsHash, MROWNER, MRSEAM, TEE_TCB_SVN, TD_ATTRIBUTES, XFAM, compose hash, app-id, instance-id, PPID of the leaf PCK certificate |
| `quote.dat` | `boot1-getquote1`'s quote trimmed to the signed 4935 bytes |
| `captures/` | the raw `POST /GetQuote` answers (`boot1-getquote{1,2}.json`, 8000-byte quotes), their nonces and report_data, and `GET /Info` (`boot1-info.json`) |
| `pcs/` | Intel PCS collateral, recorded with `pcsrecord` at 18:50:21Z, 2 s after the second quote. FMSPC `00806f050000`, TDX TCB `UpToDate`, QE `UpToDate`, no advisories |
| `predicted-rtmr12.json` | the output of `predict_rtmr12.py` for this capture: RTMR1 and RTMR2 from `disk.raw`, each event digest equal to the log |

## How it was captured

The same method as the spike (`../README.md`, "How it was captured"), with the spike's disk tarballs reused:

- VM `sealed-spike-c3s4-2`, `--machine-type=c3-standard-4 --confidential-compute-type=TDX --maintenance-policy=TERMINATE`,
  image `sealed-spike-dstack-0-6-1`, 10 GB pd-balanced boot disk.
- `--create-disk` for a 20 GB data disk and a 1 GB shared disk, both pd-balanced and auto-delete, from temporary
  images of the spike's tarballs.
- `--no-service-account --no-scopes`, metadata `block-project-ssh-keys=true,enable-oslogin=false,serial-port-enable=false`.
- Tag `sealed-spike`, vTPM and integrity monitoring on, Secure Boot off.
- tcp:8080 open only to the operator's /32.

Times (UTC, 2026-10-28):
- create call 18:49:18, running 18:49:30
- `/info` answered 18:50:17 (59 s after the create call)
- quotes 18:50:18 and 18:50:19, `/Info` 18:50:21, collateral recorded 18:50:21
- delete call 18:50:50, deleted 18:53:05
