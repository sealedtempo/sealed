# attest test fixtures

## quotes/ (third party, Apache-2.0)

Copied unchanged from `github.com/google/go-tdx-guest` at commit `23b3eac9db39ba4e1df1426bacb3bfa3a7018e97`
(module version `v0.3.2-0.20261014222600-23b3eac9db39`), `testing/testdata/`. Copyright 2023 Google LLC,
licensed under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0).

| file here | upstream file | what it is |
|---|---|---|
| `quotes/v4_spr_e4.dat` | `tdx_prod_quote_SPR_E4.dat` | production TDX quote v4, Sapphire Rapids, FMSPC 50806f000000 |
| `quotes/v5_sample.dat` | `quote_sample_v5.dat` | TDX 1.5 quote v5, FMSPC 90c06f000000 |
| `quotes/v4_gce_cos113.dat` | `ccel/cos-113-tdx-quote.dat` | TDX quote v4 from a Google Compute Engine C3 VM (COS 113), FMSPC 00806f050000 |

## pcs/ (recorded Intel PCS responses)

Real Intel PCS collateral for each quote above (TCB info, QE identity, PCK CRL, Intel SGX Root CA CRL), recorded
on 2026-10-28 with `go run ./verifier/internal/tools/pcsrecord -out verifier/attest/testdata/pcs/<name> <quote>`.
Each directory is a collateral cache directory in the `CachingGetter` on-disk format (one JSON file per URL,
named `sha256(url).json`; only the issuer-chain headers and Content-Type are kept). `recorded.json` holds the
recording time; tests verify at that time so the results never depend on the wall clock. The bodies are
Intel-signed and are re-verified on every use.

Expected results at the recording time (tests assert these):

- `v5_sample`: verifies, TDX TCB `UpToDate`, QE `UpToDate`.
- `v4_gce_cos113`: verifies, TDX TCB `OutOfDate` with advisories, so the default policy rejects it.
- `v4_spr_e4`: signature and chain verify, but no TCB level matches, so verification fails closed.

## rtmr3/

`vectors.py` (ours) computes dstack event log v1 golden vectors with Python hashlib: the dstack note's vectors
(docs/notes/dstack.md section 6.3, key provider `none`), the exact Sealed sequence (key provider `tpm`) and the
three report_data constructions. `vectors.json` is its output (`python3 -I vectors.py > vectors.json`).

## gcp/ (real capture, upstream dstack 0.6.1 image)

A real quote, event log and `/Info` output from a hello-world stack on Google Cloud `c3-standard-4` TDX in
`us-central1-a`, captured 2026-10-28 by the runtime spike, plus a second boot of the same VM. The OS image is the
upstream dstack 0.6.1 prod image (D-016: spike only, never registered). `TestRealGCPGolden` in
`golden_gcp_test.go` verifies it offline: TDX TCB `UpToDate`, measurementsHash, TD attributes and XFAM,
report_data, and the RTMR3 sequence with key provider `tpm`. Details and capture steps: `gcp/README.md`.
