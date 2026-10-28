# gcp/ golden capture: dstack 0.6.1 on Google Cloud C3 TDX

Real TDX quotes, event logs and guest-agent `/Info` output from a hello-world stack, captured on 2026-10-28 for
the Sealed runtime spike (build spec 5.1, phase 3). `TestRealGCPGolden` (`../../golden_gcp_test.go`) verifies all
four GetQuote captures offline against the recorded Intel collateral in `pcs/`, with the `tcb_policy` of
`config/defaults.yaml`, and checks each event log against its quote. `TestRealGCPGoldenRejects` runs the failure
paths on the same quote. The TypeScript tests (`packages/core/test/dstack.test.ts`, `runtime/agent/test/dstack.test.ts`)
read the same files and assert the same quoteHash and eventLogHash.

**The OS image is upstream dstack 0.6.1** (`mkosi-os-v0.6.1` prod UKI, `os_image_hash`
`ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6`), not a Sealed production image. Per D-016 it was
used only for this spike. **Never register its measurements onchain.** A Sealed image built without NVIDIA and
ZFS has a different UKI, so it has a different RTMR1/RTMR2 and measurementsHash.

## Environment

| | |
|---|---|
| Date | 2026-10-28, boot 1 at 17:56Z, boot 2 (stop/start of the same VM) at 18:01Z |
| Cloud | Google Compute Engine, test customer project, region `us-central1`, zone `us-central1-a` |
| Machine | `c3-standard-4` (4 vCPU, 16 GiB, Intel Sapphire Rapids), `--confidential-compute-type=TDX`, `--maintenance-policy=TERMINATE`, on-demand |
| Shielded VM | vTPM on, integrity monitoring on, Secure Boot off (GCE defaults for this image) |
| Disks | 10 GB pd-balanced boot (the dstack `disk.raw`), 20 GB pd-balanced data (GPT, one partition `dstack-data`), 1 GB pd-balanced shared (FAT32 label `DSTACKSHR`). All NVMe |
| Metadata | `block-project-ssh-keys=true`, `enable-oslogin=false`, `serial-port-enable=false`; no service account, no scopes |
| Network | `default` VPC with an ephemeral external IP (Docker Hub pull); tcp:8080 open only to the operator's /32 |
| Guest | dstack 0.6.1, kernel `6.18.40-dstack`, `key_provider: tpm`, event log v1 |
| Quote | TDX quote v4, ECDSA-P256 attestation key, TEE type 0x81, FMSPC `00806f050000`; TDX TCB `UpToDate` and QE `UpToDate` against Intel PCS at 18:06:45Z |

## Files

| file | what it is |
|---|---|
| `app-compose.json` | the exact bytes put on the DSTACKSHR disk. CJSON per INTERFACES 6, no trailing newline. `sha256` = stackHash = compose-hash event = `e21d29755b5a37c7dea8fd81d302ac0d8219e693c4b08e332db3f05add852e28` |
| `quote.dat` | boot 1, first quote. The raw dstack quote with its trailing zero padding cut off: 4935 bytes = 48 header + 584 TD body + 4 length + 4299 signature data. This is what sealed-agent sends (`DstackClient.getQuote` trims with `trimQuote` from @sealed/core, the rule of `attest.TrimQuote`); `ParseQuote` refuses the padded form |
| `quote-raw.hex` | the same quote exactly as `POST /GetQuote` returned it: 8000 bytes, the last 3065 all zero. `quoteHash` (INTERFACES 2) is over the trimmed bytes |
| `eventlog.json` | the `event_log` string of that GetQuote response, unchanged: 45 entries, 16/7/12 firmware CCEL entries for RTMR0/1/2 (digests only) and the 10 RTMR3 runtime events |
| `report_data.txt`, `nonce.txt` | `report_data = sha256("sealed/spike/v1" || nonce[32]) || 32 zero bytes` (the INTERFACES 3 shape with a spike-only tag) |
| `info.json` | `GET /Info` from boot 1, unchanged. `tcb_info` is a JSON string with mrtd, rtmr0-3, event_log and app_compose. `app_cert` is the public certificate the guest agent made at boot |
| `expected.json` | the values `TestRealGCPGolden` asserts: the four captures with their capture times (UTC), the signed and GetQuote lengths, the TCB result, quoteHash and eventLogHash of `quote.dat` / `eventlog.json`, measurementsHash, RTMR3, compose hash, app-id, instance-id, TD_ATTRIBUTES and XFAM. The test verifies at the collateral recording time from `pcs/recorded.json` (18:06:45Z, 4 to 9 minutes after the captures), because the collateral cache only serves entries fetched no more than a minute after "now" |
| `pcs/` | Intel PCS collateral for `quote.dat` (TCB info, QE identity, PCK CRL, root CA CRL; the boot 2 quotes need the same four URLs), recorded with `go run ./verifier/internal/tools/pcsrecord -out verifier/attest/testdata/gcp/pcs verifier/attest/testdata/gcp/quote.dat` |
| `captures/` | every raw response: `boot{1,2}-getquote{1,2}.json` (full GetQuote JSON: quote, event_log, report_data, vm_config), `boot{1,2}-info.json`, and the nonce and report_data of each quote |
| `tools/` | the scripts used: `server.py` (the in-CVM proxy, embedded verbatim in app-compose.json), `make_shared.py` (writes app-compose.json and the other shared-disk files), `capture.py` (nonces, report_data, the HTTP calls), `check_capture.py` (offline Python checks of one capture), `predict_rtmr12.py` (computes RTMR1 and RTMR2 from `disk.raw` alone and compares them with a capture) |

## Values

| | value |
|---|---|
| MRTD | `f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3` |
| RTMR0 | `4b08605d192148837400c4eee71f46b65ff960eaaf63494c472c4ddc4482d7c23d8671913ebec4b85c6edb89aa232662` |
| RTMR1 | `fea84c84e8093e0444d63d0ae25e35e4324f84c643f00340d06f2522876f2ae579f5dfefd3fe389c033b7ee0d96fbcf3` |
| RTMR2 | `961f79aaacd74ebcb350f909e5165e13186c4c405af0df5a5504221a43f32c159eeebd675eb46dc370aa0803a714239c` |
| RTMR3 | `7794b40a1f9727c2867faafe0e77dd98a60d9509839b45b658739fce257dd6497f2998caf8b8c77289337928506726a5` |
| measurementsHash | `keccak256(mrtd \|\| rtmr0 \|\| rtmr1 \|\| rtmr2)` = `0xd63f2a83b0334d1a026b7a1af14fe5c8d5628fea1e761e14a900ebd0c19e3c49` (`cast keccak`) |
| TD_ATTRIBUTES | `0000001000000000` (u64 LE `0x10000000`: only SEPT_VE_DISABLE, bit 28; DEBUG = 0) |
| XFAM | `e702060000000000` (u64 LE `0x602e7`: bits 0,1,2,5,6,7,9,17,18 = x87, SSE, AVX, AVX-512 (3 bits), PKRU, AMX TILECFG/TILEDATA) |
| MRSIGNERSEAM, SEAM attributes, MRCONFIGID, MROWNERCONFIG | all zero |
| MROWNER | `1b203465ce7e175b86bcc5554b34c6a792e92c225cfe4f25f97a035a0728e529ab75b12b44621d02bc97ecb728fd8098` (set by Google, stable across the reboot; not known whether it varies per VM or project) |
| MRSEAM | `ab62561a173acbd18ee50ff37750db44184c6cf5e886df74247cc575e163b04c34b9e18374757c235affa614d4127f6b`, TEE_TCB_SVN `0f010a00000000000000000000000000` |
| app-id / instance-id | `e21d29755b5a37c7dea8fd81d302ac0d8219e693` (compose hash prefix; `.instance_info` had no app_id) / `8a7611f1c2c7db0d907ad426f8a0df2de9137908` |

RTMR3 events, in order (v1 digests, all recomputed and replayed equal to the quote): `system-preparing`, `app-id`
(20 bytes), `compose-hash` (32, = stackHash), `gpu-policy-hash` (`44136fa3...aff8a`), `instance-id` (20),
`boot-mr-done`, `key-provider` (`{"name":"tpm","id":""}`), `storage-fs` (`ext4`), `storage-encrypted` (`1`),
`system-ready`. This is the INTERFACES 6 sequence exactly. Replaying the RTMR0-2 digests of the CCEL entries from
zero also gives the quote's RTMR0-2.

RTMR1 and RTMR2 depend only on the boot disk image. `tools/predict_rtmr12.py <disk.raw> captures/boot1-getquote1.json`
rebuilds every RTMR1 and RTMR2 event from the release `disk.raw` and gets the quote's values:
- RTMR1 holds the "Calling EFI Application from Boot Option" action, a separator, the boot disk GPT, the SHA-384
  Authenticode of `BOOTX64.EFI` (the UKI) and of its `.linux` PE, and the two ExitBootServices actions.
- RTMR2 holds systemd-stub's name and content digests of the UKI sections `.linux`, `.osrel`, `.cmdline` (it
  carries `dstack.rootfs_hash`), `.initrd`, `.uname` and `.sbat`.

MRTD (Google's TDX firmware) and RTMR0 (firmware configuration, ACPI tables, boot variables) come from the
platform, not from the image.

Boot 2 (`gcloud compute instances stop` then `start`) gave byte-identical MRTD, RTMR0-3, MROWNER, MRSEAM,
TD_ATTRIBUTES, XFAM and event log digests. Only REPORTDATA (a new nonce) and the signature differ. With
`key_provider: tpm` the guest unsealed its seed from the vTPM (PCR policy sha256:0,2,14), opened the existing
LUKS data disk and brought the same container back.

## How it was captured

1. `dstack-0.6.1-uki.tar.gz` from the `Dstack-TEE/dstack` release `mkosi-os-v0.6.1` (`gh release download`),
   sha256 `42ce3692a3ca779bf12506130a142ce2ffc749ac5e1d0261c54750616e625fa8`; `digest.txt` = sha256(`sha256sum.txt`) =
   `ec43cb8c...`, and `disk.raw` matches its line in `sha256sum.txt` (`430adff7...`).
2. `disk.raw` re-tarred (GNU format, no xattrs) and imported as a GCE image with guest OS features
   `UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC`. The shared disk was built on macOS: `truncate -s 8M`,
   `mkfs.fat -F 32 -n DSTACKSHR`, `mcopy` of `app-compose.json`, `.sys-config.json` (`kms_urls` and `gateway_urls`
   empty, `vm_config` with `gcp_measurement` from the release files) and `.instance_info` (random
   `instance_id_seed` only). The data disk: `truncate -s 10M`, `sgdisk -o -n 1:0:0 -t 1:8300 -c 1:dstack-data`.
   Both were imported as temporary images and then created as disks with the VM.
3. The compose runs one service, `docker.io/library/python@sha256:5789aa194f757888f41fa3d48e14b6feaa1b57c0af0b56fcb1372d6474d3bff0`
   (`python:3.12-alpine` index digest), with `/var/run/dstack.sock` mounted read-only and `tools/server.py` as
   `python3 -u -c`. `GET /quote?report_data=<hex>` forwards `POST /GetQuote` on the socket; `GET /info` forwards
   `GET /Info`.
4. After the serial console showed `Container dstack-spike-1 Started`, `tools/capture.py` made two quotes with
   fresh nonces and one `/Info` call; then the VM was stopped, started, and captured again the same way.
5. `tools/check_capture.py` checked each capture (header, TD body, padding, RTMR0-3 replay, event sequence,
   compose hash, report_data, `/Info` consistency); `pcsrecord` recorded the collateral; the VM was deleted.
