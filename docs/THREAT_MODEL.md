# Sealed threat model

Status: 2026-10-28. Written from the code on the integration branches and the build and review notes. The runtime has been tested locally and on a local Tempo devnet with the dstack simulator; the first boots on Google Cloud TDX hardware are in progress. Statements that depend on a real boot are marked (first boot). At block 46329286 no platform image and no app is registered on mainnet yet, so the measurements below are not recorded yet.

## What Sealed protects

Your data stays in your cloud account. Apps run in confidential VMs, we have no access path, and outbound traffic only reaches destinations you approve. Your wallet approves exactly which builds can unlock your data.

Concretely:

1. Secret release (P1). Customer secrets (app secrets, the data-disk key, the enclave signer seed, the gate password hash) are released only to a VM that proves with an Intel TDX quote that it runs an approved non-debug image and exactly the stack the customer's wallet approved onchain, built only from active releases. The customer's own key broker makes this decision in the customer's own project; the platform is not in that path.
2. No operator access path (P2, P4). Production VMs have no SSH daemon, no getty or login, no serial console login, no OS Login, no project SSH keys and no service account. The platform's deployer identity in the customer project can create, start, stop and delete `sealed-*` VMs, disks and addresses, but cannot read Secret Manager, use the KMS key, change the key broker, attach a service account or open a shell.
3. Egress control (P3). App containers have no route to the internet. The only proxy and DNS server, sealed-egress, enforces per-caller allowlists that are part of the measured stack, so every destination an app can reach is something the customer approved by approving the stackHash.
4. Content-free reporting (P5). What leaves the VM toward the platform is health, counts (egress counts use only allowlist entries and a fixed vocabulary), signed usage totals and attestation evidence. Prompts and outputs never leave llm-gateway; app data never leaves the VM except to approved destinations.
5. Onchain privacy (P6). Deployment records hold hashes and addresses only: no customer config, IPs, hostnames or domains.
6. Independent verification (P7). Anyone with an evidence bundle and a Tempo RPC can re-check a deployment with `sealed verify`, without trusting the platform ([VERIFY.md](VERIFY.md)).
7. Data at rest. App data is on a LUKS2 disk whose key only an attested VM running an approved stack can obtain, so a stopped VM's disk, a snapshot or a copy is unreadable to the operator and to anyone with project access.

## What Sealed does not protect

Confidential VMs do not stop physical attacks on the server, bugs inside apps, or a cloud provider with physical access. In addition:

- A malicious or buggy app that the customer approved can misuse the data it is given, within its egress allowlist. Review of the catalog lowers this risk; it does not remove it.
- Destinations the customer adds to `egressAdditions` are trusted with whatever apps send them. Routes marked "data leaves your cloud" (external LLM providers) do exactly that.
- Prompts sent to `relay/<model>` leave the customer's cloud: they go to the platform relay, which runs in its own attested VM, and on to an attested inference provider. Provider attestation covers the provider's serving stack, not what a provider does outside it.
- TDX side channels, CPU microcode and TDX module bugs are covered only by Intel's TCB status reporting: the key broker and verifier reject quotes whose TCB status the policy does not allow (`UpToDate`, `SWHardeningNeeded` by default).
- Availability. The operator, Google or the customer can stop or delete VMs, block the network or withhold the Tempo RPC. Data on the persistent disk stays encrypted. Billing fails closed, so blocking the chain or the platform api ends in the payment-needed page, not in free usage.
- Integrity of the data disk against rollback. aes-xts has no integrity protection, so whoever controls the disk can corrupt blocks or restore an older copy of the whole disk. They cannot read or forge plaintext.
- Supply chain before the catalog. An upstream project that ships malicious code in a pinned version is caught only by review, SBOMs and scans, and can be stopped by revoking the release onchain. That is mitigation, not prevention.
- What the customer approves. A wallet approval covers exactly the stackHash it signs. A customer who approves in the console trusts the console to show the stack it composed; `sealed deploy --plan` composes the same stack locally from the public releases and prints its stackHash, so the approval can be checked before it is signed.
- Weak gate passwords. The gate is bcrypt with rate limits; the password's strength is the customer's choice (`sealed secrets set gate --generate` makes a strong one).

## Trust anchors

| anchor | trusted for | if it fails | rotate or revoke |
|---|---|---|---|
| Intel TDX hardware, TDX module and Intel PCS collateral | quotes chain to Intel's root CA; TCB status | forged or stale quotes would pass | Intel TCB recovery; `tcb_policy` in `config/defaults.yaml` and the key broker's `SEALED_TCB_ALLOWED` |
| Google Cloud firmware (TDVF) | the code measured into MRTD and RTMR0 | firmware that misreports measurements | new image registration after a firmware change (below) |
| Google Cloud vTPM | sealing the dstack system disk seed (`key_provider: tpm`, D-017) | container layers on the system disk could be read by whoever controls the vTPM | not rotatable by us; app data does not depend on it |
| dstack OS image (MRTD, RTMR0 to RTMR2) | open-source build from Apache-2.0 sources without NVIDIA and ZFS (D-016), registered in PlatformRegistry with `isDebug` by the owner; the customer's approval names the imageId, so a newly registered image runs only stacks a customer approved with it | a bad image could leak secrets after release | `revokeImage`; register a new image |
| Release bundles | public source, digest-pinned images, SBOMs and scans, cosign keyless signature logged in Rekor, SLSA provenance, catalog review | approved apps could misbehave within their allowlist | `revokeRelease`, which blocks every stack that uses it at its next boot |
| Customer wallet | sole signer of `approveStack`, `revokeStack` and the access-key authorization | an attacker with the wallet can approve a malicious stack | move to a new wallet and re-bootstrap |
| Customer key broker and its Google Cloud project | runs from a digest-pinned public image with its own service account; customer address and RPC set by the customer | whoever controls the customer project can read the customer's own secrets | customer redeploys it |
| Tempo chain and the RPC endpoint | onchain state for approvals, images and releases | a lying RPC could claim approvals | the customer chooses the RPC at bootstrap; every check of one decision reads one pinned block |
| OPS key and release CI | the only registrar of releases | a malicious release could be published (it still needs the customer's approval of a stack using it) | `revokeRegistrar`, `revokeRelease` |
| Oracle key (method 1 records) | attests that the platform verified evidence before recording it | misleading deployment records; never secret release | `removeSigner`; method 2 removes this anchor ([ZK_UPGRADE.md](ZK_UPGRADE.md)) |
| Platform | availability, the console, the relay | outages; misleading records (caught by `sealed verify`) | none needed for secret safety |

## Measurement chain on Google Cloud

Runtime: dstack 0.6.1 (`Dstack-TEE/dstack`, Apache-2.0, D-015) on Google Cloud C3 Intel TDX. The production OS image is our own build of the dstack mkosi sources with the NVIDIA and ZFS components removed and `storage_fs: ext4` (D-016). The upstream image is used only for the hello-world spike and is never registered as approved.

### Registers

| register | measures | on Google Cloud |
|---|---|---|
| MRTD | the TD's initial firmware | Google's TDVF build. Google is in the TCB for MRTD; dstack's tooling cannot compute it for GCP. |
| RTMR0 | firmware configuration, TD HOB and ACPI tables | Google firmware; may vary with the machine shape (CPU count, memory), so images are registered per machine type if it does (first boot) |
| RTMR1, RTMR2 | the boot path of dstack's unified kernel image: kernel, initrd, command line | the split between the two registers on Google's firmware is recorded at first boot. The command line pins the dm-verity root hash of the read-only root filesystem, so the whole OS is covered |
| RTMR3 | runtime events extended by dstack | replayed from the event log, never pinned (below) |

`measurementsHash = keccak256(mrtd || rtmr0 || rtmr1 || rtmr2)` (48 bytes each) is stored by `PlatformRegistry.addImage`, which also emits the raw registers. The key broker and the verifier require the quote's registers to hash to `getImage(imageId).measurementsHash` and `isApprovedImage(imageId)` to be true (Active and not debug).

### Trust on first use

dstack's measurement tooling cannot precompute MRTD and RTMR0 to RTMR2 for Google's firmware, so the expected values are recorded trust-on-first-use (TOFU):

1. Build the production image in CI from pinned sources and record its UKI hash.
2. Boot it at least twice per machine type on C3 TDX with a hello-world stack, verify each quote with Intel collateral, and capture MRTD and RTMR0 to RTMR2.
3. Require the boots to agree, then register the image with `addImage(..., isDebug = false, sourceURI)` naming the build.
4. Record the values here.

Until Google's signed firmware endorsements are checked (planned, not implemented: the verifier pins MRTD through PlatformRegistry only), a TOFU value is trusted because two clean boots on Google's hardware produced it, not because it was derived from source. A Google firmware update changes MRTD or RTMR0 and needs a new registration. Deprecating or revoking the old image stops every deployment on it at once (contract review logic-F7), so new images are registered and stacks moved before an old image is retired.

| image | machine type | MRTD | RTMR0 | RTMR1 | RTMR2 | recorded |
|---|---|---|---|---|---|---|
| none registered yet | | | | | | |

### RTMR3 and the compose hash

dstack extends RTMR3 at boot with a fixed event sequence: `system-preparing`, `app-id`, `compose-hash`, `gpu-policy-hash`, `instance-id`, `boot-mr-done`, `key-provider` (`{"name":"tpm","id":""}`), `storage-fs` (`ext4`), `storage-encrypted` (`1`), `system-ready`. Each digest is `sha384(le32(0x08000001) || ":" || name || ":" || payload)` folded from 48 zero bytes.

- The `compose-hash` payload is `sha256(app-compose.json)`, which is the stackHash. The composed stack includes every image digest, every fragment, the egress allowlists, the Caddyfile, the host firewall script and the public config, so one changed byte anywhere changes the stackHash.
- The key broker and the verifier require exactly this sequence, reject unknown events, replay it to the quote's RTMR3 and require the compose hash to equal `sha256(appCompose)`. RTMR3 differs per VM (`instance-id` mixes in the vTPM key), so it is replayed, never pinned.
- Apps cannot extend RTMR3 (dstack 0.6 removed `EmitEvent`), and only sealed-agent can reach the dstack socket.
- Unmeasured host inputs on the dstack shared disk (`.sys-config.json`, `.instance_info`, `.user-config`) never drive a security decision. A registry mirror set there can only cause a denial of service, because every image is pulled by digest.

### TD attributes and TCB

- TD_ATTRIBUTES: no debug bits, not migratable, `SEPT_VE_DISABLE` set, no reserved bits. Debug images are registered with `isDebug = true` and never receive anything: the broker has no debug secret set. Google Cloud does not launch debug TDs.
- TCB: the quote, the PCK chain, the QE report, collateral signatures and expiry, and the CRLs are checked; the platform, TDX module and QE TCB levels are combined as Intel's QVL does and must be in `tcb_policy.allowed_statuses`.

### report_data bindings (D-010, D-047)

Every construction is `sha256(tag || fields)` followed by 32 zero bytes, so a quote made for one purpose is useless for another:

| use | fields |
|---|---|
| key release, `sealed/kb-release/v1` | broker nonce (single use, 5 minutes), ephemeral X25519 public key |
| evidence, `sealed/evidence/v1` | stackHash, configHash, enclaveSigner, nonce2, `uint64be(attestedAt)` |
| live attest, `sealed/attest/v1` | caller's nonce, `sha256` of the served TLS certificate's public key, enclaveSigner |

### Disks (D-017)

- dstack system disk: encrypted by dstack with a seed sealed in the Google vTPM under PCRs 0, 2 and 14 (PCR14 carries the same runtime events as RTMR3). It holds container images and container layers. Its protection trusts Google's vTPM. App data should not be written there: every app volume is a bind of the encrypted data disk.
- `sealed-data` disk: LUKS2, aes-xts-plain64, 512-bit, with the volume key and keyslot passphrase derived by HKDF from the broker's `diskKey`. Before mounting, the agent requires exactly one expected keyslot, one crypt segment, no tokens and no reencryption requirement, and after unlocking it checks the device-mapper table for exactly the derived key. A header the host prepared (cipher_null, a keyslot any passphrase opens, a volume key the host knows) is never mounted. `diskKey` is HMAC-SHA256 by the customer's Cloud KMS over `sealed/disk/v1 || deploymentId`, so it survives reboots and its root key never leaves KMS.

## The key release decision

The key broker answers `POST /v1/release` only after these checks pass, in this order, each logged with its reason and hashes to the customer's Cloud Logging. An allowed release is answered only after its log entry is written.

1. The nonce was issued by this broker, is unexpired and unused. It is consumed before any other check.
2. The quote verifies with Intel collateral and its TCB status is allowed. No quote, a non-TDX blob or a simulated quote is refused by production builds (the production binary has no development flags at all).
3. report_data equals the key-release construction for this nonce and ephemeral key.
4. The image exists, its measurements match, it is not a debug image, the TD has no debug or migratable attributes, and it is approved.
5. RTMR3 replays with the exact event sequence and its compose hash equals `sha256(appCompose)`.
6. The composer recomputes `appCompose` byte for byte from the config and the onchain releases' bundles, each fetched by the D-046 asset rule and accepted only when its sha256 equals the onchain bundleHash.
7. `config.customer` is the bootstrap customer, and the config names this broker's chain and registries.
8. `isStackApproved(customer, stackHash)` holds, and the approval's releaseIds and imageId equal the config's (D-014).
9. Only then: the stack's declared secrets, `diskKey` and `signerSeed`, HPKE-sealed (X25519, HKDF-SHA256, AES-256-GCM) to the ephemeral key with the nonce as associated data.

## Attacks and the tests that cover them

Tests named here run in CI or on the local devnet. Acceptance tests A3, A7, A8, A9, A10 and A11 repeat the important cases on mainnet and Google Cloud; they have not run yet.

| attack | defense | tests |
|---|---|---|
| Operator boots a modified stack (one changed byte in a fragment, manifest, egress policy or config) to obtain secrets | stackHash changes; broker recomputes the stack; no approval for it | composer `TestOneByteChangesStackHash` (every byte of 410 fragment, 90 egress, 622 manifest and 495 config variants); key broker `TestDenials`; verifier `TestComposedStackEndToEnd` (changed config byte, changed app-compose byte); A7 |
| Host swaps the compose on the shared disk, or edits the event log | RTMR3 replay with the exact sequence; compose hash equals `sha256(appCompose)` | `TestDenials` (`rtmr3_replay`, `compose_mismatch`, extra, missing and reordered events, key provider `none`); verifier "event log reordered" |
| Debug image, or debug TD claiming the production image | `isDebug` images never approved; TD_ATTRIBUTES checked | `TestDenials` (`image_debug` cases); verifier `td_attributes`; A7 |
| Unregistered, revoked or foreign image | measurementsHash and `isApprovedImage` | `TestDenials`; verifier "quote with another image's measurements", "revoked image" |
| Boot with a revoked release | `isStackApproved` requires active releases; approval release set must equal the config's | `TestDenials` (release revoked after approval); verifier "revoked release"; A7 |
| Undo a revocation by re-approving the stack with another release list | the first approval fixes releaseIds and imageId (CR-2) | `contracts/test/audit/AuditLogic.t.sol`, `AuditCrypto.t.sol` (crypto-SEAL-01, logic-F2) |
| Customer revokes approval; the next boot still gets secrets | approval checked at every boot | `TestDenials` (revoked approval); verifier "revoked approval, then re-approved"; A7 |
| Replay an old quote or request to the broker | single-use 5-minute nonce in report_data, consumed first | key broker replay tests (a released body replayed; 32 concurrent copies give exactly one 200) |
| Reuse a quote made for evidence or live attest as a key-release quote | domain-separated report_data | `TestDenials` (evidence and attest constructions refused); verifier report_data vectors |
| Relabel old evidence as fresh, or register a record signed before a revocation | attestedAt bound in report_data (D-047); oracle 15-minute window; `maxAttestationAge`; `AttestedBeforeApproval` (CR-3); `QuoteReused` (CR-4) | verifier "attestedAt relabelled"; `contracts/test/audit/AuditCrypto.t.sol` |
| Network attacker intercepts released secrets | HPKE to the ephemeral key bound in the quote | shared Go and TypeScript HPKE vectors (`packages/core/test/fixtures/hpke-vector.json`, `key-broker/testdata/hpke-kb-release-vector.json`) |
| Tampered quote, unsigned trailing bytes, out-of-date TCB | Intel collateral, CRLs, TCB policy; exact signed quote only | `TestDenials` with real GCE quotes and recorded Intel PCS collateral; `verifier/attest` tests |
| A non-confidential VM asks for secrets | no valid TDX quote | `TestDenials` (no quote, non-TDX bytes, simulated quote on a production broker); `scripts/iam-checks/check.sh` non-confidential check; A3 |
| Catalog or mirror serves a different bundle | sha256 against the onchain bundleHash | `TestDenials` (`bundle_hash_mismatch`); verifier "served bundle changed by one byte", "another app's bundle"; `verifier/bundles` tests |
| App exfiltrates to an unapproved host, a raw IP, the metadata server, through DNS tunneling or DNS rebinding | internal networks; egress allowlist; DNS filtering; address checks before every dial | `runtime/egress/egress_test.go`: `TestNonAllowlistedHostIsBlockedAndCounted`, `TestRawIPAndMetadataAreBlocked`, `TestMetadataBlockedEvenWhenAllowedNameResolvesToIt`, `TestRandomSubdomainLookupIsNXDOMAINAndCounted`, `TestRebindingBlockedOverPlainHTTP`, `TestKeepAliveSecondRequestIsCheckedToo`, `TestLocalNetworksAreDenied`; A8 |
| Egress counts leak hostnames or IPs an app chose | fixed stats vocabulary | `TestChosenNamesAndIPsNeverReachStats`, `TestLogsCarryCountsOnly` |
| One app starves the agent's or payer's connections | per-caller limits and reserved slots | `TestOneCallerCannotStarveTheAgent`, `TestProxyRequestRateIsPerCaller` |
| App reaches another app's database or worker | per-app internal networks (D-041) | composer `TestAppsCannotReachOtherAppsServices` |
| App fragment asks for privileges: privileged, devices, capabilities, host network, ports, bind or socket mounts, host environment interpolation | composer rejects the fragment | composer `TestEveryForbiddenKeyIsRejected`, `TestForbiddenMountsAndValues` |
| App reads another app's secrets | one read-only file mount per declared secret (D-042); agent refuses a compose that crosses owners | composer `TestServiceGetsOnlyDeclaredSecretFiles`; agent `secretMounts.test.ts`, `secrets.test.ts` |
| Host prepares a data-disk header it can open | LUKS2 header and device-mapper table checks | agent `disk.test.ts` |
| Brute force, replay or theft of the gate | bcrypt; per-client and global rate limits; per-boot HMAC cookie; Caddy strips the gate's credentials and cookie before the app | agent `gate.test.ts`, `bcrypt.test.ts`; composer `TestCaddyfileWithRealCaddy` (real Caddy 2.11.7, with four deliberate template breakages failing it) |
| A container on the edge network reaches the internet directly | measured host rules allow forwarding from the edge subnet only from sealed-egress, and fail closed | composer `TestHostRulesScript`, `TestHostRulesScriptRuns` |
| Platform deployer account reads a secret, changes the key broker, attaches a service account or opens a shell | custom roles with `sealed-*` name conditions; no secret, KMS, Cloud Run or service-account permissions | `scripts/iam-checks/check.sh` (`check_test.go`: eleven misconfigurations each fail; `policy_test.go` renders the Terraform IAM module); A3 |
| Shell access to a production VM | dstack production image without sshd, getty or login; VM with no service account, OS Login off, serial port and its logging off, project SSH keys blocked, TDX on | CLI deploy tests (the instance check refuses any of these settings); iam-checks "no shell"; A3 |
| Usage-hash squatting or underpayment of fees | dedupe per `(deploymentId, usageHash, appId)` (CR-1); `topUpFees` (CR-7); settle a leg only at `usagePaid >= fee` (V-1); leg token fixed (V-2) | `AuditFunds.t.sol`, `AuditLogic.t.sol`; agent `settler.test.ts`, `payments.anvil.test.ts` |
| Enclave signer key overspends | access-key daily limit and allowed calls; exact approvals reset to zero; FeeSplitter caps; one shared budget with the payer (D-048) | FeeSplitter fuzz and invariant tests; agent `budget.test.ts`; payer `shared-budget.test.ts`; A9 |
| Malicious relay or provider | provider attestation per request; payer verifies the relay every 15 minutes and pins its TLS key | relay and payer test suites; A10 (forced attestation failure) |
| Compromised oracle key | not in the secret-release path; `sealed verify` re-checks evidence itself | `OracleSignatureVerifier` tests; verifier `onchain_record` |

## Residual risks

From the contract review (`contracts/README.md`; no critical or high findings, every medium fixed):

- Fees keep flowing for a deployment whose stack, release or image was revoked, because past usage must stay payable (logic-F3, funds-F-07). Levers: `setMaintainerShare(app, 0)`, `setMaintainer`, `closeDeployment`.
- Daily caps use fixed UTC days, so up to twice a daily cap can be paid around midnight (funds-F-04).
- Closed deployments cannot pay; the stop flow settles the last period before `closeDeployment` (funds-F-05).
- TIP-20 issuer policies (TIP-403) can block a recipient or FeeSplitter itself (funds-F-08).
- deploymentId is not bound onchain to `(customer, stackHash, salt)`; the oracle recomputes it before signing (crypto-SEAL-04).
- Method 1 trusts a single oracle signer, and events do not name the signer; the indexer recovers it from transaction input (crypto-SEAL-07). Method 2 needs a report_data v2 first (crypto-SEAL-03, [ZK_UPGRADE.md](ZK_UPGRADE.md)).
- A signed record stays registrable by anyone for `maxAttestationAge` (1 day) unless ops lowers it (logic-F8, partly fixed by CR-3).
- Deprecating an image stops every deployment on it at once (logic-F7).

From the runtime, key broker and verifier work:

- Google firmware and the vTPM are in the TCB; MRTD and RTMR0 to RTMR2 are TOFU until Google's firmware endorsements are checked.
- TD_ATTRIBUTES and XFAM are checked generically, not pinned per image. TDX 1.5 relaunch-advised statuses are reported as OutOfDate, which the default policy rejects.
- If current C3 hosts report OutOfDate, a customer who allows it (`SEALED_TCB_ALLOWED`) accepts known TCB issues; that is the customer's security decision.
- An Intel PCS outage makes the broker answer `quote_invalid` instead of a retryable error; the agent retries after a minute.
- The broker keeps nonces in memory on one Cloud Run instance (`--max-instances 1`) and has no per-client rate limit on `GET /v1/nonce` (eviction keeps issuance working under a flood).
- A stack upgrade changes the deploymentId, so a new disk key and enclave signer: the upgraded stack cannot open the old data disk until a migration path is decided. This affects availability, not confidentiality.
- The broker and verifiers recompute only stacks of their own composer version; each version bump needs a broker image built with it before stacks of that version can boot.
- `same_as` gives one app another app's secret by design (D-043); catalog review checks every reference.
- sealed-egress identifies callers by source address. This relies on `NET_RAW` being dropped and on separate app networks; proxy credentials exist but are off.
- Egress counts are allowed to leave the VM (P5), so an app can signal a few bits through how often it is blocked.
- Boot progress appears on the VM's serial output, which project members with the right permission can read; nothing secret is printed there and container output never reaches it.
- The relay sees prompts sent to `relay/*` inside its attested VM; per-request charges are final; NEAR AI model and GPU evidence are not checked; a relay error after a paid retry counts as spent.

## Open items before production

- First real boots: measurements, unpadded quotes from dstack, a real GCP quote golden test (`TestRealGCPGolden` is skipped today), per-file secret binds from `/run`, the agent's device rules, Docker's embedded DNS forwarding to sealed-egress on internal networks, and Caddy's admin socket permissions.
- The in-VM sealed-verifierd's egress allowlist lacks the release asset hosts (`github.com:443`, `release-assets.githubusercontent.com:443`), so it cannot recompute the relay's stack and the payer refuses the relay until the composer adds them or a mirror under an allowed host is used.
- Google firmware endorsement checks for MRTD.
- Acceptance tests A2 to A13 on mainnet and Google Cloud.
- The fresh security review of the key broker, sealed-egress and sealed-agent.
