# Verifying a Sealed deployment

Every app is built from public source, pinned, scanned, signed and reviewed. You can verify that exactly that build is what runs. This document shows how.

A verification needs an evidence bundle (or the deployment's live attest URL) and a Tempo RPC endpoint. It does not need the platform, an account or any credential. The platform api is used only if you ask it to resolve a `dep_` alias or to download the evidence for you, and even then nothing it says is trusted: every check runs against Intel's root of trust, the Tempo chain and the public release bundles.

Limits: confidential VMs do not stop physical attacks on the server, bugs inside apps, or a cloud provider with physical access. A passing verification shows which code runs and who approved it; it does not show that the code is free of bugs.

## What a passing verification shows

- The quote was produced by an Intel TDX confidential VM whose TCB status the policy allows, and is not a debug TD.
- The VM booted a platform image registered and approved in PlatformRegistry, identified by its MRTD and RTMR0 to RTMR2.
- The VM runs exactly the stack whose hash is in RTMR3, and that stack is what the deterministic composer produces from the public config and the onchain releases' bundles, byte for byte.
- Every release is active onchain, and the customer's wallet approved exactly this stack with exactly these releases and this image.
- The onchain deployment record matches the evidence, and the quote binds the enclave signer that pays fees.
- With `--live`: the quote is fresh (it binds your nonce), and the TLS key you connected to belongs to that VM.

## Get the CLI

```sh
git clone https://github.com/sealedtempo/sealed && cd sealed
go build -o sealed ./cli/cmd/sealed       # Go 1.26 or newer
./sealed version
```

The CLI embeds `config/defaults.yaml` (TCB policy, release asset base, public RPC) and `contracts/deployments/tempo-mainnet.json` (registry addresses), so it needs no configuration for mainnet. It contacts only the Tempo RPC, Intel PCS (`api.trustedservices.intel.com`, `certificates.trustedservices.intel.com`) and the release asset host (`github.com`, which redirects to `release-assets.githubusercontent.com`), plus the attest URL in live mode. Intel collateral and bundles are cached under your user cache directory.

## Commands

```sh
# Evidence file (downloaded from the console, or given to you by the customer)
sealed verify --deployment 0x<deploymentId> --evidence evidence.json

# Your own RPC endpoint instead of https://rpc.tempo.xyz
sealed verify --deployment 0x<deploymentId> --evidence evidence.json --rpc https://<your tempo rpc>

# Live: fresh nonce and TLS key binding against the running VM
sealed verify --deployment 0x<deploymentId> --live https://attest.<ip-with-dashes>.sslip.io/attest

# Both in one run (two reports, both must pass)
sealed verify --deployment 0x<deploymentId> --evidence evidence.json --live https://attest.<ip-with-dashes>.sslip.io/attest

# Pin what you expect, and bound the evidence age
sealed verify --deployment 0x<deploymentId> --evidence evidence.json \
  --expect-customer 0x<customer wallet> --expect-apps crm,llm-gateway --max-age 26h

# Machine-readable output
sealed verify --deployment 0x<deploymentId> --evidence evidence.json --json
sealed verify --deployment 0x<deploymentId> --evidence evidence.json --report report.json

# Console alias: the api resolves dep_ to the full id, then every check runs against the chain
sealed verify --deployment dep_<8 chars> --api https://<platform api>
```

| flag | meaning |
|---|---|
| `--deployment` | the full `0x` deploymentId (trustless), or a `dep_` alias that `--api` resolves (D-032) |
| `--evidence` | a `sealed-evidence/v1` file. Without it and without `--live`, the CLI downloads the evidence from `--api` |
| `--live` | the deployment's attest URL: a fresh nonce, a new quote, and the TLS key binding |
| `--rpc` | Tempo JSON-RPC (default `chain.public_rpc_url`, `https://rpc.tempo.xyz`; also `TEMPO_RPC_URL`) |
| `--expect-customer`, `--expect-apps` | fail unless the deployment belongs to that wallet and contains those apps |
| `--max-age` | fail when the evidence is older than this; re-attestation runs every 24 hours, so `26h` is a reasonable bound |
| `--deployments`, `--defaults`, `--release-asset-base` | other chains, defaults or a bundle mirror (every bundle is still checked against its onchain bundleHash) |
| `--json`, `--report` | print JSON, or also write it to a file |

Exit status: 0 when every check passed, 1 when any check failed, 2 for a usage error. The `--dev-*` flags accept dev simulator quotes and exist only with `SEALED_DEV_SIM=1`; a report produced that way says `SIMULATED` and proves nothing about real hardware.

## What each check means

Every check is listed in the report, and a check whose inputs are missing fails (fail closed). All chain reads of one verification use the block shown in the report.

| check | passes when | why it matters |
|---|---|---|
| `bundle` | the evidence or `/attest` document has every field, with the right schema and sizes; JSON keys are unique and case-exact | no ambiguous input reaches the checks |
| `chain` | the RPC's chain id, the bundle's and the config's are equal, and their registry addresses are the verifier's | evidence from another chain or a look-alike contract fails |
| `quote_hash` | `sha256(quote)` equals `quoteHash` | ties the quote to the record |
| `quote` | the quote is exactly the signed quote; its signature, PCK chain to Intel's root, QE report, collateral and CRLs verify; the TCB status is in the policy | proves real TDX hardware with an allowed TCB |
| `td_attributes` | no debug bits, not migratable, `SEPT_VE_DISABLE` set, no reserved bits | a debug TD can be inspected by the host |
| `image_measurements` | `keccak256(mrtd, rtmr0, rtmr1, rtmr2)` equals `PlatformRegistry.getImage(imageId).measurementsHash` | the VM booted that registered OS image |
| `image_approved` | `isApprovedImage(imageId)` and the image is not a debug image | the image is still approved |
| `event_log_hash` | `sha256(CJSON(eventLog))` equals `eventLogHash` | ties the event log to the record |
| `rtmr3` | the event log replays to the quote's RTMR3 with exactly dstack's event sequence | the event log is the one the hardware measured |
| `compose_hash` | the `compose-hash` event equals `sha256(appCompose)` equals `stackHash` | the VM runs exactly this app-compose.json |
| `config_hash` | `sha256(CJSON(config))` equals `configHash` | the public config is the one bound in the quote |
| `config_binding` | the bundle's customer, imageId, chainId and releaseIds equal the config's; apps are sorted | no field outside the config can disagree with it |
| `deployment_id` | `keccak256(abi.encode(customer, stackHash, salt))` equals the deploymentId, and the one you asked for | the id names this customer's stack |
| `report_data` | the quote's report_data is `sha256("sealed/evidence/v1" \|\| stackHash \|\| configHash \|\| enclaveSigner \|\| nonce2 \|\| uint64be(attestedAt))` then 32 zero bytes (D-047), or the live construction | the quote was made for this evidence, at this time, for this signer |
| `freshness` | evidence: attestedAt within `--max-age` and at most 5 minutes in the future; live: your nonce is bound | old evidence cannot be passed off as new |
| `releases_active` | each release exists, is active (or deprecated) and belongs to the app named in the config | a revoked release fails |
| `stack_recompute` | each bundle, fetched from `<release_asset_base>/<app>-v<version>/<app>-<version>.bundle.tar`, hashes to the onchain bundleHash and names the same app and version; the composer then recomputes appCompose byte for byte | the stack is built only from published, signed releases with nothing added |
| `stack_approved` | `DeploymentRegistry.isStackApproved(customer, stackHash)` | the customer's wallet approved this stack, unrevoked and unexpired |
| `approval_releases` | `getStackApproval` names exactly the config's releases and image (D-014) | the approval covers what runs |
| `onchain_record` | `getDeployment` is Active and its customer, stackHash, imageId, configHash and enclaveSigner match; in evidence mode also eventLogHash, quoteHash and attestedAt equal to `lastAttestedAt` | the onchain record describes this evidence |
| `expected_customer`, `expected_apps` | only when requested | you check the deployment you meant |
| `live_fetch`, `tls_binding` | live only: `/attest` fetched over TLS from a public host, and `tlsPubKeyHash` equals the sha256 of the public key of the certificate served on that same connection | the endpoint you talk to is inside the attested VM |

## Verify a release

Each release in a stack can be checked on its own:

```sh
B=https://github.com/sealedtempo/sealed/releases/download
APP=crm VERSION=<version>                                  # version as published in AppRegistry
curl -LO $B/$APP-v$VERSION/$APP-$VERSION.bundle.tar
curl -LO $B/$APP-v$VERSION/$APP-$VERSION.bundle.tar.sigstore.json
curl -LO $B/$APP-v$VERSION/$APP-$VERSION.bundle.tar.intoto.jsonl

# Signed by the release workflow of the public repo (cosign keyless, logged in Rekor)
cosign verify-blob --bundle $APP-$VERSION.bundle.tar.sigstore.json \
  --certificate-identity https://github.com/sealedtempo/sealed/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com $APP-$VERSION.bundle.tar

# Built by GitHub Actions from this repository (SLSA provenance)
slsa-verifier verify-artifact $APP-$VERSION.bundle.tar \
  --provenance-path $APP-$VERSION.bundle.tar.intoto.jsonl --source-uri github.com/sealedtempo/sealed

# The bundle is the one registered onchain, and it rebuilds from source
sha256sum $APP-$VERSION.bundle.tar                         # = bundleHash from AppRegistry.getRelease (step 7 below)
sealed release build $APP --check $VERSION
```

`sealed release build <app> --check <version>` rebuilds the bundle from your checkout of the commit the release was built from (the SBOMs and scans come from the published bundle, since CI generates them) and requires the result to equal the onchain bundleHash byte for byte. The release notes of each GitHub Release print the same commands with the exact file names.

## Verify without the platform, with standard tools only

`sealed verify` is itself a platform-independent check. To avoid depending on our code for any step, each check can be repeated with general tools: `jq`, `sha256sum`, Python 3, Foundry's `cast`, Google's `go-tdx-guest` quote checker, and the composer from this repository for the stack recomputation (it is the one piece that must be ours, because the stackHash is defined by it). Set up:

```sh
E=evidence.json
RPC=https://rpc.tempo.xyz
PLATFORM=0x18AB956ea44757587896dfD25632FB3e89F7002d
APPS=0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43
DEPLOYMENTS=0x254eFB9d1809A95Ec6d233cC57b3a10849bd2C8E
cast chain-id --rpc-url $RPC                          # 4217
jq -r .chainId,.contracts $E                          # same chain, same registries
```

1. Hashes in the bundle.

   ```sh
   jq -j .appCompose $E | sha256sum                   # = .stackHash
   jq -r .quote $E | cut -c3- | xxd -r -p > quote.bin
   sha256sum quote.bin                                # = .quoteHash
   ```

   For `configHash` and `eventLogHash`, canonical JSON is sorted ASCII keys, no whitespace, integers only, and escapes only for `"`, `\` and control characters:

   ```sh
   python3 -c 'import json,sys,hashlib; e=json.load(open(sys.argv[1])); c=lambda v: json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(); print(hashlib.sha256(c(e["config"])).hexdigest(), hashlib.sha256(c(e["eventLog"])).hexdigest())' $E
   ```

2. Quote fields. A TDX quote v4 has a 48-byte header and then the TD report body; v5 has 6 more bytes (body type and size) before it.

   ```python
   import json, sys
   e = json.load(open(sys.argv[1])); q = bytes.fromhex(e["quote"][2:])
   v = int.from_bytes(q[0:2], "little"); b = 48 if v == 4 else 54
   f = lambda off, n: q[b + off : b + off + n].hex()
   print("td_attributes", f(120, 8)); print("mrtd", f(136, 48))
   for i in range(4): print(f"rtmr{i}", f(328 + 48 * i, 48))
   print("report_data", f(520, 64))
   ```

3. The quote's signature chain and TCB, with Google's checker (the same library version this repository pins), requiring the fields you just parsed so you know they are the signed ones:

   ```sh
   go run github.com/google/go-tdx-guest/tools/check@v0.3.2-0.20261014222600-23b3eac9db39 \
     -in quote.bin -get_collateral=true -check_crl=true \
     -mr_td <mrtd> -rtmrs <rtmr0>,<rtmr1>,<rtmr2>,<rtmr3> -report_data <report_data> -td_attributes <td_attributes>
   ```

   Its TCB rule is its own; compare the reported status with `tcb_policy.allowed_statuses` in `config/defaults.yaml` (`UpToDate`, `SWHardeningNeeded`). Check that td_attributes has no debug bit (bit 0 of the first byte).

4. RTMR3 replay and the compose hash:

   ```python
   import json, sys, hashlib
   e = json.load(open(sys.argv[1])); h = lambda s: bytes.fromhex(s.removeprefix("0x"))
   acc = bytes(48)
   for ev in e["eventLog"]:
       if ev["imr"] != 3: continue
       d = hashlib.sha384(b"\x01\x00\x00\x08:" + ev["event"].encode() + b":" + h(ev["event_payload"])).digest()
       assert d.hex() == ev["digest"].lower(), ev["event"]
       acc = hashlib.sha384(acc + d).digest()
       if ev["event"] == "compose-hash": print("compose-hash", ev["event_payload"])
   print("rtmr3", acc.hex())                          # = rtmr3 from step 2
   print([ev["event"] for ev in e["eventLog"] if ev["imr"] == 3])
   ```

   The event names must be exactly `system-preparing`, `app-id`, `compose-hash`, `gpu-policy-hash`, `instance-id`, `boot-mr-done`, `key-provider`, `storage-fs`, `storage-encrypted`, `system-ready`, and the compose hash must equal the stackHash.

5. report_data:

   ```python
   import json, sys, hashlib
   e = json.load(open(sys.argv[1])); h = lambda s: bytes.fromhex(s.removeprefix("0x"))
   rd = hashlib.sha256(b"sealed/evidence/v1" + h(e["stackHash"]) + h(e["configHash"]) + h(e["enclaveSigner"])
                       + h(e["nonce2"]) + e["attestedAt"].to_bytes(8, "big")).digest() + bytes(32)
   print(rd.hex())                                    # = report_data from step 2
   ```

6. Image, ids and onchain state:

   ```sh
   IMAGE=$(jq -r .imageId $E); CUSTOMER=$(jq -r .customer $E); STACK=$(jq -r .stackHash $E)
   SALT=$(jq -r .config.salt $E); ID=$(jq -r .deploymentId $E)
   cast keccak 0x<mrtd><rtmr0><rtmr1><rtmr2>          # = measurementsHash below
   cast call $PLATFORM "getImage(bytes32)((bytes32,bool,uint8,uint64,string,string,string))" $IMAGE --rpc-url $RPC
   cast call $PLATFORM "isApprovedImage(bytes32)(bool)" $IMAGE --rpc-url $RPC
   cast keccak $(cast abi-encode "f(address,bytes32,bytes32)" $CUSTOMER $STACK $SALT)   # = deploymentId
   cast call $DEPLOYMENTS "isStackApproved(address,bytes32)(bool)" $CUSTOMER $STACK --rpc-url $RPC
   cast call $DEPLOYMENTS "getStackApproval(address,bytes32)(bytes32[],bytes32,uint64,bool,uint64)" $CUSTOMER $STACK --rpc-url $RPC
   cast call $DEPLOYMENTS "getDeployment(bytes32)((bytes32,address,uint64,uint8,uint8,uint8,bytes32,bytes32,bytes32,bytes32,bytes32,address,uint64,uint64,uint64))" $ID --rpc-url $RPC
   ```

   `getImage` returns `(measurementsHash, isDebug, status, addedAt, name, version, sourceURI)` with status 1 = Active. `getStackApproval` returns `(releaseIds, imageId, expiry, revoked, approvedAt)`: the release set must equal the config's `apps[].releaseId` and the imageId the config's. `getDeployment` returns `(deploymentId, customer, attestedAt, method, lastMethod, status, stackHash, imageId, quoteHash, eventLogHash, configHash, enclaveSigner, lastAttestedAt, registeredAt, closedAt)` with status 1 = Active; compare each field with the evidence.

7. Releases and bundles, for each `config.apps[]` entry:

   ```sh
   REL=0x<releaseId>
   cast call $APPS "getRelease(bytes32)((bytes32,bytes32,bytes32,bytes32,uint8,uint64,string,string,string))" $REL --rpc-url $RPC
   cast call $APPS "isActiveRelease(bytes32)(bool)" $REL --rpc-url $RPC
   cast keccak <app slug>                             # = appId in getRelease
   cast keccak $(cast abi-encode "f(bytes32,string,bytes32)" <appId> <version> <bundleHash>)   # = releaseId
   ```

   `getRelease` returns `(appId, bundleHash, egressPolicyHash, sbomHash, status, publishedAt, version, provenanceURI, signatureURI)`. Download each bundle as in "Verify a release", check its sha256 against `bundleHash`, and verify its signature and provenance.

8. Recompute the stack. Use a checkout whose composer version equals `config.composerVersion` (`go run ./runtime/composer/cmd/sealed-compose version`):

   ```sh
   jq .config $E > config.json
   go run ./runtime/composer/cmd/sealed-compose compose --config config.json \
     --bundle crm-<version>.bundle.tar --bundle llm-gateway-<version>.bundle.tar --out stack
   jq -j .appCompose $E | cmp - stack/app-compose.json && echo identical
   ```

   The composer reads only the config and the bundles, so the same inputs give the same bytes on any machine. `--print egress`, `--print caddyfile` and `--print stack` show the measured egress allowlists, the Caddy routes and the stack layout that are inside that stackHash.

If every step matches, you have checked the deployment with your own tools against Intel's root of trust and the Tempo chain.

## What verification does not show

- That the apps are free of bugs or behave well with the data they are given. Read the app's README, LICENSE-NOTICE and egress policy, and the customer's `egressAdditions` in the config.
- That the hardware resists physical attacks, or that the cloud provider with physical access does not attack it.
- The platform image's MRTD and RTMR0 to RTMR2 are recorded trust-on-first-use on Google Cloud, so `image_measurements` shows the VM booted the registered image, and the trust in that registration is described in [THREAT_MODEL.md](THREAT_MODEL.md#trust-on-first-use).
- Evidence shows the state at `attestedAt`. Use `--live` for the state now, and `onchain_record`'s `lastAttestedAt` for the latest heartbeat.
