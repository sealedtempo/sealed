# gcp/c3-standard-8-1: the first c3-standard-8 TDX VM

The first VM of machine type `c3-standard-8`, the shape customer deployments run (D-037). It was captured on
2026-10-28 to find out what changes with the machine type. `TestRealGCPMachineTypes`
(`../../../golden_gcp_machines_test.go`) verifies both quotes offline against the collateral in `pcs/` and compares
this VM with the two c3-standard-4 VMs (`../` and `../c3-standard-4-2/`).

**The OS image is upstream dstack 0.6.1** (`os_image_hash` `ec43cb8c...`). Per D-016, **never register these
measurements onchain**, including the measurementsHash below.

## What changed with the machine type

The boot image and the shared and data disk images are the same as for the two c3-standard-4 VMs, and the shared disk
has the same `instance_id_seed`. This VM also ran on **the same physical platform as `../c3-standard-4-2/`**: both
leaf PCK certificates have PPID `77bad2a988e00c7d0a6b2e0929f4b9f5`. So the differences in the table come from the
machine type and the instance, not from the host or the inputs.

| | c3-standard-8 (this VM) | c3-standard-4 (both VMs) |
|---|---|---|
| Machine | 8 vCPU, 32 GiB, Intel Sapphire Rapids, `us-central1-a`, on-demand | 4 vCPU, 16 GiB, same |
| MRTD | `f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3` | **same** |
| RTMR0 | `2074615297d6e87ec1dbbb764635ee3bb06b00b0fbc13f35bead969b811355f749156b1a88f9716300db68b1ddae1f71` | **differs** (`4b08605d...aa232662`) |
| RTMR1 | `fea84c84e8093e0444d63d0ae25e35e4324f84c643f00340d06f2522876f2ae579f5dfefd3fe389c033b7ee0d96fbcf3` | **same** |
| RTMR2 | `961f79aaacd74ebcb350f909e5165e13186c4c405af0df5a5504221a43f32c159eeebd675eb46dc370aa0803a714239c` | **same** |
| measurementsHash | `0x85fdf6009863bfb158d4e497970712cd8711c779f522bebdf66aebfe62870bed` | **differs** (`0xd63f2a83...c19e3c49`) |
| TD_ATTRIBUTES | `0000001000000000` (SEPT_VE_DISABLE only) | **same** |
| XFAM | `e702060000000000` (`0x602e7`) | **same** |
| MRSEAM, TEE_TCB_SVN | `ab62561a...d4127f6b`, `0f010a00000000000000000000000000` | **same** |
| MRCONFIGID, MROWNERCONFIG, MRSIGNERSEAM | all zero | same |
| MROWNER | `f6b381de4ae5a9267354c9d3adb3871278cc4eb35ee271768d8eb25061f813900eb1d47078a2000d31958c7b52142fab` | differs (per instance) |
| instance-id event | `22b775803afc92bf22dee7a47300b6c7a91e0f9d` | differs (per instance) |
| RTMR3 | `06911dd58cef4a571a19d905073e4c5bf5010c62b20cbdfe7d7470ef59302c459c8f76019c9148f868e45340b00be92a` | differs, only through instance-id |

### Which RTMR0 entries change

RTMR0 has the same 16 CCEL entries on both machine types, in the same order and with the same event types. Four
digests differ. The payloads are stripped, so the meaning of each entry is inferred from its event type and from
dstack's label:

| # | entry | c3-standard-4 | c3-standard-8 |
|---|---|---|---|
| 0 | EV_EFI_HANDOFF_TABLES2 (`0x8000000b`): in TDVF this is the TD HOB, which carries the memory map | `d587edd1...` | `39e89cd8...` |
| 8 | EV_PLATFORM_CONFIG_FLAGS (`0xa`) `acpi-loader` | `ee0cc4f8...` | `e828c43e...` |
| 9 | EV_PLATFORM_CONFIG_FLAGS `acpi-rsdp` | `957129f8...` | `4b7f3aad...` |
| 10 | EV_PLATFORM_CONFIG_FLAGS `acpi-tables` | `70cb7693...` | `b3eaba03...` |

These entries do not change: the firmware volume (EV_EFI_PLATFORM_FIRMWARE_BLOB2), the five
EV_EFI_VARIABLE_DRIVER_CONFIG entries, the separator and the five EV_EFI_VARIABLE_BOOT
entries. The guest kernel log (serial port, not committed) fits this:
- The HOB covers 16 GiB on c3-standard-4 and 32 GiB on c3-standard-8 (SRAT memory up to `0x43fffffff` and
  `0x83fffffff`).
- The ACPI tables that list CPUs grow with the vCPU count: APIC (MADT) `0x96` to `0xb6` bytes, SRAT `0xe8` to
  `0x128`, and the second SSDT `0x9dd` to `0xb6e`. DSDT, FACP and the other tables keep their size.

The payloads of RTMR0-2 entries are stripped in dstack's event log (digests only), so RTMR0 cannot be recomputed
from the log. It also cannot be computed from the image, because Google builds the HOB and the ACPI tables.

`tools/predict_rtmr12.py <disk.raw> captures/boot1-getquote1.json` (in `../tools/`) rebuilds every RTMR1 and RTMR2
event of this quote from the release `disk.raw`. Its output is `predicted-rtmr12.json`. The machine type does not
change RTMR1 or RTMR2.

## Files

| file | what it is |
|---|---|
| `expected.json` | the values the test asserts: capture times, lengths, TCB result, quoteHash of `quote.dat`, all registers, measurementsHash, MROWNER, MRSEAM, TEE_TCB_SVN, TD_ATTRIBUTES, XFAM, compose hash, app-id, instance-id, PPID of the leaf PCK certificate |
| `quote.dat` | `boot1-getquote1`'s quote trimmed to the signed 4935 bytes |
| `captures/` | the raw `POST /GetQuote` answers (`boot1-getquote{1,2}.json`, 8000-byte quotes), their nonces and report_data, and `GET /Info` (`boot1-info.json`) |
| `pcs/` | Intel PCS collateral, recorded with `pcsrecord` at 18:54:31Z, 1 s after the second quote. FMSPC `00806f050000`, TDX TCB `UpToDate`, QE `UpToDate`, no advisories |
| `predicted-rtmr12.json` | the output of `predict_rtmr12.py` for this capture: RTMR1 and RTMR2 from `disk.raw`, each event digest equal to the log |

## How it was captured

The same flags as `../c3-standard-4-2/` with `--machine-type=c3-standard-8`, VM `sealed-spike-c3s8-1`.

Times (UTC, 2026-10-28):
- create call 18:53:32, running 18:53:44
- `/info` answered 18:54:28 (56 s after the create call)
- quotes 18:54:29 and 18:54:30, `/Info` 18:54:31, collateral recorded 18:54:31
- delete call 18:55:08, deleted 18:57:37
