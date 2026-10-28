# key broker TDX fixtures

Copied unchanged from `verifier/attest/testdata/` so the key broker tests do not depend on another component's
test files.

## quotes/ (third party, Apache-2.0)

From `github.com/google/go-tdx-guest` at commit `23b3eac9db39ba4e1df1426bacb3bfa3a7018e97` (module version
`v0.3.2-0.20261014222600-23b3eac9db39`), `testing/testdata/`. Copyright 2023 Google LLC, licensed under the Apache
License 2.0 (https://www.apache.org/licenses/LICENSE-2.0).

| file | upstream file | what it is |
|---|---|---|
| `quotes/v5_sample.dat` | `quote_sample_v5.dat` | TDX 1.5 quote v5, FMSPC 90c06f000000 |
| `quotes/v4_gce_cos113.dat` | `ccel/cos-113-tdx-quote.dat` | TDX quote v4 from a Google Compute Engine C3 VM, padded to 8000 bytes |

## pcs/ (recorded Intel PCS responses)

Real Intel PCS collateral for each quote, recorded on 2026-10-28 by the verifier's `pcsrecord` tool, in the
`attest.CachingGetter` on-disk format. Tests verify at the time in `recorded.json`, so results never depend on the
wall clock. Expected at that time:

- `v5_sample`: verifies, TCB `UpToDate`. Its report_data is not a key-release construction, so the broker answers
  `report_data_mismatch`: a real quote passes the quote check and still gets nothing.
- `v4_gce_cos113` (zero padding trimmed): verifies, TCB `OutOfDate`, so the default policy answers `tcb_status`.
  Untrimmed, it carries unsigned trailing bytes and is `quote_invalid`.
