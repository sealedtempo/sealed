# Sealed contracts

Onchain registries and fee splitting for Sealed on Tempo mainnet (chain id 4217). A Foundry project.

| Contract | Role |
|---|---|
| `PlatformRegistry` | Measured platform (guest OS) images: MRTD and RTMR0-2 hashed onchain, Active / Deprecated / Revoked. |
| `AppRegistry` | Catalog apps (owner) and their releases (REGISTRAR_ROLE = ops / release CI). |
| `OracleSignatureVerifier` | Attestation method 1: an allowed oracle signer's ECDSA signature over an EIP-712 digest. |
| `DeploymentRegistry` | Customer stack approvals, attested deployment records, heartbeats, close. Pluggable verifier per method id. |
| `FeeSplitter` | Per-app usage fees from a deployment's customer or enclave signer, split maintainer / treasury, pull withdrawals. |

All five are non-upgradeable, owned by OWNER through `Ownable2Step` (renounce disabled), expose
`VERSION = "1.0.0"`, use custom errors only, and emit an event for every state change with the fields an
indexer needs to rebuild state from events alone. Onchain deployment data is hashes and addresses only (P6).

## Versions

| Item | Pin | Why |
|---|---|---|
| Solidity | `0.8.38` (`solc_version`, exact `pragma`) | latest stable 0.8.x (2026-10-22) |
| EVM version | `osaka` | Tempo executes Osaka (docs: quickstart/evm-compatibility) |
| Optimizer | on, 200 runs, legacy codegen (no via-IR), `bytecode_hash = "ipfs"` | must match for verification |
| OpenZeppelin Contracts | `5.7.0` (Soldeer `@openzeppelin-contracts`) | latest stable 5.x |
| forge-std | `1.17.0` (Soldeer) | latest |
| Foundry | `1.8.6` (`make foundry-check`, D-053) | `network = "tempo"`, `hardfork = "tempo:t12"` (mainnet's; `tempo:t13` from 2026-11-03 15:00 UTC, see Tempo notes) |

Dependencies are Soldeer packages pinned with checksums in `soldeer.lock`; `dependencies/` is gitignored and
restored with `make deps` (`forge soldeer install`). No git submodules. In a non-interactive shell Soldeer 0.10's
progress UI can fail with `IO operation: not connected`; prefix with `RUST_LOG=info` to use the plain logger.

## Layout

```
src/
  IAttestationVerifier.sol      interface + AttestationMethods (ORACLE_SIG_V1 = 1, ZK_DCAP_V1 = 2)
  OracleSignatureVerifier.sol   PlatformRegistry.sol  AppRegistry.sol  DeploymentRegistry.sol  FeeSplitter.sol
  interfaces/                   IPlatformRegistry, IAppRegistry, IDeploymentRegistry (types + cross-contract views)
  utils/OwnableNoRenounce.sol   Ownable2Step with renounceOwnership disabled
script/
  Deploy.s.sol                  deploy + wire, writes deployments/<network>.json
  RegisterCatalog.s.sol         addImage / registerApp from a JSON catalog (idempotent)
  TransferOwnership.s.sol       Ownable2Step handover to a multisig (TransferOwnership, AcceptOwnership)
  record-deployment.sh          merges tx hashes, blocks, gas, fees from a broadcast into the deployments file
  local-e2e.sh                  full flow on a local `anvil --network tempo`
  check-catalog.sh              preflight of a catalog file against the app manifests (read only)
  rehearse-catalog.sh           RegisterCatalog.s.sol with the mainnet catalog on a local node, gas per transaction
test/                           unit, fuzz, EIP-712, ZK-method, script, integration tests
test/invariant/                 handler-based invariants (FeeSplitter on mock and real TIP-20 tokens, approval
                                logic, deployment lifecycle, catalog access control, oracle verifier, strangers)
test/fork/                      Tempo mainnet fork tests: real pathUSD and USDC.e, and the deployed contracts
test/fixtures/catalog.example.json  test fixture catalog (placeholder measurements, old app entries)
catalog/catalog.mainnet.json    the mainnet catalog: the six seed apps, registered by OWNER
abi/                            exported ABIs (`make abi`)
deployments/                    tempo-mainnet.json after deploy (source of truth for addresses)
```

## Ids and hashes (D-008, `docs/INTERFACES.md` section 2)

| Id | Formula | Where |
|---|---|---|
| appId | `keccak256(bytes(slug))` | checked by `registerApp` (`computeAppId`) |
| releaseId | `keccak256(abi.encode(appId, version, bundleHash))` | computed by `publishRelease` (`computeReleaseId`) |
| deploymentId | `keccak256(abi.encode(customer, stackHash, salt))` | offchain; any unique non-zero id accepted |
| imageId | `keccak256(abi.encode(name, version, measurementsHash))` | offchain; any unique non-zero id accepted |
| measurementsHash | `keccak256(abi.encodePacked(mrtd, rtmr0, rtmr1, rtmr2))`, each exactly 48 bytes | computed and stored by `addImage` (D-007) |

## Contracts

### PlatformRegistry

- `addImage(imageId, name, version, mrtd, rtmr0, rtmr1, rtmr2, isDebug, sourceURI)` owner. Each measurement must be
  48 bytes; `imageId` non-zero and never reused (also after revoke); `name` and `version` non-empty; the
  measurement set must not belong to any earlier image, whatever its status (`MeasurementsAlreadyRegistered`), so a
  revoked image cannot come back under a new id. Stores `measurementsHash` and emits `ImageAdded` with the raw
  registers and the hash. Parameters are `memory` (not `calldata`) to stay inside the legacy-codegen stack limit;
  the ABI is the same.
- `deprecateImage(imageId)` (Active -> Deprecated), `revokeImage(imageId, reason)` (Active/Deprecated -> Revoked,
  terminal) owner. **Both stop every running stack on the image at once** (images follow the spec literally,
  D-013): deprecating an image is an outage-level action, not a soft phase-out.
- `isApprovedImage(imageId)`: Active and not debug. `getImage(imageId)` (reverts for unknown), `imageStatus`,
  `imageByMeasurements(measurementsHash)`, `computeMeasurementsHash`.

### AppRegistry

- `registerApp(appId, slug, name, licenseSpdx, maintainer, maintainerShareBps, metadataURI)` owner;
  `appId == keccak256(bytes(slug))`, share <= 5000 bps, maintainer non-zero, no duplicates.
- `setMaintainer` (current maintainer or owner), `setMaintainerShare` (owner, <= 5000), `setMetadataURI` (owner).
- `grantRegistrar` / `revokeRegistrar` owner. `DEFAULT_ADMIN_ROLE` is never granted, so AccessControl's
  `grantRole` / `revokeRole` always revert; a registrar can `renounceRole` itself. The role set survives ownership
  transfers.
- `publishRelease(appId, version, bundleHash, egressPolicyHash, sbomHash, provenanceURI, signatureURI)`
  REGISTRAR_ROLE; returns `releaseId`. Rejects unknown apps, empty version, zero bundleHash, duplicate releaseId,
  a version already used by the app and a bundleHash already published by the app (both also if that release was
  revoked), so a revoked bundle cannot come back as a new version.
- `deprecateRelease` (Active -> Deprecated), `revokeRelease(releaseId, reason)` (-> Revoked, terminal) owner.
- **D-013**: `isActiveRelease` = Active or Deprecated (deprecated releases keep working in approved stacks);
  `isApprovableRelease` = Active only (gates `approveStack`); `latestRelease(appId)` = newest Active release or 0.
- Views: `getApp`, `getRelease`, `appExists`, `appCount`, `appAt`, `releaseCount`, `releaseAt`, `releaseByVersion`,
  `releaseByBundle`, `releaseStatus`, `appOfRelease`, `payoutInfo`. `latestRelease` walks the app's releases (view
  only, never called onchain).

### DeploymentRegistry

- `approveStack(stackHash, releaseIds, imageId, expiry)` by the customer: 1..16 distinct approvable releases, an
  approved image, `expiry == 0` (none) or in the future. **The first approval of a (customer, stackHash) fixes its
  release list and image**: stackHash is the measured compose, which commits to the config's releaseIds and
  imageId. A re-approval must repeat them in the same order (`ReleasesChanged`, `ImageMismatch`), needs each
  release still Active or Deprecated (`isActiveRelease`, so a stack with a since-deprecated release can be extended
  or restored, D-013) and an approved image, sets the new expiry and clears a revocation. So a revoked release
  stays a kill switch for every deployment of the stack. `revokeStack(stackHash)`; a re-approval restores the
  stack's deployments that were not closed (use `closeDeployment` to stop one for good). Not affected by pause.
- `isStackApproved(customer, stackHash)`: exists, not revoked, `block.timestamp < expiry` (or no expiry), image
  approved, every release `isActiveRelease`. `getStackApproval` returns `(releaseIds, imageId, expiry, revoked,
  approvedAt)`.
- `registerDeployment(Record r, method, evidence)` whenNotPaused, anyone may submit. Checks: non-zero unused
  deploymentId, non-zero customer and enclaveSigner, `isStackApproved`, `r.imageId` equals the approval's image,
  `attestedAt <= now + 5 min` and `now - attestedAt <= maxAttestationAge` (default 1 day, owner-settable 1 s..30
  days), `attestedAt + 5 min >= approvedAt` of the approval (`AttestedBeforeApproval`: a record signed before a
  revoke and re-approval cannot be used later), `verifiers[method].verify(recordDigest(r), evidence)`.
- `heartbeat(deploymentId, quoteHash, attestedAt, method, evidence)` whenNotPaused: Active, stack still approved,
  `attestedAt` strictly after the last one and fresh, `quoteHash` different from the current one (`QuoteReused`),
  valid evidence over `heartbeatDigest`. Updates `quoteHash`, `lastAttestedAt`, `lastMethod`. The approval's image
  and releases cannot change after registration, so heartbeat needs no image check.
- `closeDeployment(id)` by the customer or owner, also while paused. Closed is terminal; ids are never reused.
- `appInDeployment(id, appId)`: deployment exists (Active or Closed) and a release of the approval belongs to
  `appId`; the approval's list is fixed, so this is the set the deployment was registered with. Release, image and
  approval status are not checked. `getDeployment`, `deploymentParties` (status, customer, enclaveSigner; used by
  FeeSplitter).
- `setVerifier(method, address)` owner (method 0 invalid, address must have code, `address(0)` unsets),
  `setMaxAttestationAge`, `pause` / `unpause`.

### OracleSignatureVerifier (method 1)

`verify(digest, evidence)` returns true when `evidence == abi.encode(bytes signature)` (canonical 160-byte encoding),
the signature is 65 bytes, `ECDSA.tryRecover(digest, signature)` succeeds (low-s, v in {27, 28}) and the signer is
allowed. The digest is the EIP-712 digest itself: no re-hashing, no EIP-191 prefix. Never reverts. Owner
`addSigner` / `removeSigner`.

### FeeSplitter

- Constructor `(owner, deploymentRegistry, appRegistry, feeToken, treasury, perPaymentCap, perDeploymentDailyCap)`
  allowlists `feeToken` (pathUSD, 6 decimals; defaults 5 USD = 5_000_000 and 20 USD/day = 20_000_000). Requires
  `appRegistry == deploymentRegistry.appRegistry()` (`AppRegistryMismatch`).
- `payFees(deploymentId, appId, token, amount, usageHash)` whenNotPaused, nonReentrant: deployment Active, caller is
  its customer or enclave signer, app in the deployment, token allowed, `0 < amount <= perPaymentCap`, the
  deployment's total for `(token, block.timestamp / 1 days)` stays within the daily cap, **payFees opens each
  `(deploymentId, usageHash, appId)` once** (`UsageAlreadyPaid`), `usageHash != 0`. Pulls with `safeTransferFrom`
  and requires the balance to grow by exactly `amount` (rejects fee-on-transfer tokens and TIP-20 receive-policy
  redirects). Credits
  `amount * shareBps / 10000` (rounded down) to the app's current maintainer and the rest to the current treasury;
  a maintainer address that could never withdraw (FeeSplitter itself or a TIP-20 token address) gets no share and
  the treasury gets the whole amount. Emits `Credited` per non-zero credit (with the new balance; none for a zero
  maintainer part) and `FeesPaid`.
- `topUpFees(deploymentId, appId, token, total, usageHash)` whenNotPaused, nonReentrant: raises an opened leg to
  `total` and pulls only `total - usagePaid` (approve that difference). Same payer, deployment, app, token and cap
  checks as `payFees`; `total` is at most `perPaymentCap`, the difference counts against the daily cap and is split
  and emitted as `FeesPaid` like a payment. Reverts `UsageNotPaid` on a leg payFees has not opened and
  `NothingToTopUp` when `total <= usagePaid`, so a retried top-up never pays twice.
- `usagePaid(deploymentId, usageHash, appId)` returns the amount paid (0 = unpaid). The usage key includes the
  deployment, so the payer of one deployment cannot consume another deployment's key (a usageHash already names
  its deployment). FeeSplitter does not see the signed report, so the deployment's own payer can open a leg with
  less than its fee: settlement compares the recorded amount with the report's fee and tops a short leg up with
  `topUpFees`. Indexers sum the `FeesPaid` amounts per `(deploymentId, usageHash, appId)`; the sum equals
  `usagePaid`.
- `withdraw(token)` nonReentrant, works while paused and after a token is disallowed: pays the caller's full credit
  to the caller only. There is deliberately no `withdrawTo`: a TIP-403-blacklisted account must not be able to
  move its credit to a clean address.
- `sweepUnaccounted(token)` owner: credits `balanceOf(this) - totalCredited[token]` (direct transfers) to the
  treasury.
- `setToken`, `setCaps`, `setTreasury` (existing credits stay with the old treasury; rejects zero, FeeSplitter
  itself and TIP-20 token addresses, `InvalidTreasury`), `pause` / `unpause` owner.
- Caps are per token and per deployment over fixed UTC days: up to 2x a daily cap can be paid around midnight.
- Invariant (tested): per token, sum of credits == `totalCredited` == `balanceOf(this)`.

## Contract review (2026-10-28)

Three independent auditor agents (logic and state machine, funds and FeeSplitter, attestation and signatures)
reviewed the contracts. The two medium issues and the cheap low ones are fixed, and a verification pass over the
fixes added `topUpFees` (item 7); every PoC is replayed in `test/audit/`. Changes against the original interface
spec, all small:

1. FeeSplitter dedupes usage per `(deploymentId, usageHash, appId)` (spec: per `(usageHash, appId)`) and
   `usagePaid` returns the amount paid. A usageHash already names its deployment, so honest flows are unchanged.
2. The first `approveStack` of a `(customer, stackHash)` fixes its release list and image; a re-approval repeats
   them, may change only the expiry and clears a revocation (spec: re-approval overwrites). Re-approval checks
   `isActiveRelease` instead of `isApprovableRelease` (D-013). `heartbeat` drops the image check this makes
   redundant.
3. `registerDeployment` rejects records attested more than 5 minutes before the approval's `approvedAt`.
4. `heartbeat` rejects a `quoteHash` equal to the current one.
5. PlatformRegistry registers each measurement set once; AppRegistry publishes each `(appId, bundleHash)` once.
6. FeeSplitter's constructor requires `appRegistry == deploymentRegistry.appRegistry()`; the treasury cannot be
   FeeSplitter or a TIP-20 token address; a maintainer share owed to such an address goes to the treasury.
7. FeeSplitter adds `topUpFees` (found when the fixes were verified): the deployment's own payer can still open a
   leg with 1 base unit, and `payFees` cannot repeat a leg, so without a top-up a short leg could never be
   completed. The agent now settles a leg only at `usagePaid >= fee` and tops up the shortfall.

Rules this leaves to offchain components:
- The oracle checks D-014 (config releaseIds and imageId equal the approval's) and recomputes deploymentId from
  `config.customer` and `config.salt` before signing a Record or Heartbeat. With fixed approval content the check
  stays valid for the approval's lifetime.
- Settlement treats a `(deploymentId, usageHash, appId)` as settled only when `usagePaid` reaches the report's
  fee and tops a short leg up with `topUpFees(total = fee)`; a top-up that cannot be paid is a payment failure, so
  the grace period and the payment-needed page apply. `UsageAlreadyPaid` and `NothingToTopUp` revert the batch and
  the next settlement re-reads `usagePaid`. Access keys must be scoped to both `payFees` and `topUpFees`.
- The stop flow settles the last period before `closeDeployment` (Closed deployments cannot pay).
- go-ethereum `crypto.Sign` returns v in {0, 1}; the Go oracle adds 27.
- `lastAttestedAt` may be up to 5 minutes ahead of block time, so liveness math (`now - lastAttestedAt`) clamps at
  0. Indexers recover the oracle signer of a registration from the transaction input
  (`OracleSignatureVerifier.recoverSigner`); events do not carry it.
- Method 2 stays unset until a report_data v2 binds deploymentId, customer and a chain-anchored freshness value.

## EIP-712

Domain `{name: "Sealed DeploymentRegistry", version: "1", chainId, verifyingContract: DeploymentRegistry}`.

```
Record(bytes32 deploymentId,address customer,bytes32 stackHash,bytes32 imageId,bytes32 quoteHash,bytes32 eventLogHash,bytes32 configHash,address enclaveSigner,uint64 attestedAt)
Heartbeat(bytes32 deploymentId,bytes32 quoteHash,uint64 attestedAt)
```

`recordDigest(Record)` and `heartbeatDigest(deploymentId, quoteHash, attestedAt)` return
`keccak256("\x19\x01" || domainSeparator || keccak256(abi.encode(TYPEHASH, fields...)))`.

Known-answer vector (pinned in `test/DeploymentRegistryEIP712.t.sol`, computed independently with `cast`), for
other implementations (Go oracle, TS platform):

| Input | Value |
|---|---|
| chainId / verifyingContract | `4217` / `0x5EA1eD0000000000000000000000000000000001` |
| record | deploymentId `keccak256("deployment")`, customer `0x1111…1111`, stackHash `keccak256("stack")`, imageId `keccak256("image")`, quoteHash `keccak256("quote")`, eventLogHash `keccak256("eventlog")`, configHash `keccak256("config")`, enclaveSigner `0x2222…2222`, attestedAt `1730000000` |
| domainSeparator | `0x167ac8767ef1192a681f7e1f22a6805d72c9d61b38bd42836ede9c4cec7ceb62` |
| RECORD_TYPEHASH | `0x5006c22389c5fdb42fd699c22f11658c5ea40d3486a5bb2f8e7639b99e136c09` |
| HEARTBEAT_TYPEHASH | `0x5a6a40c52f1b097970a0b914f2d09952d22fea27be00600dacb989697a697750` |
| recordDigest | `0x5b22ad0f2f063b043d53295ce89d6b6bf35afed7ada6893a7cc27dfc4781dfcd` |
| heartbeatDigest (quoteHash `keccak256("quote-2")`, attestedAt `1730003600`) | `0xb12fb41b09faf4de1d741817dcb19ff0a34f7179feed00bb18f71e924006952d` |
| oracle signature of recordDigest by anvil key #2 (`0x3C44…93BC`) | `0xe1f5a46ede8037c8bb0b4a97fe91f07a4ca0a20558838f56fad1e6c2fd0e36a55d270090dcfe096cffa0ecf211b1f881c02bd09e7255ac17257b475d3e233f811b` |

Method-1 evidence is `abi.encode(bytes signature)`, for example `cast abi-encode 'f(bytes)' $(cast wallet sign
--no-hash $DIGEST --private-key $ORACLE_KEY)`.

## ZK readiness

Method ids live in `AttestationMethods`: `ORACLE_SIG_V1 = 1` (set at deploy), `ZK_DCAP_V1 = 2` (reserved, unset;
`Deploy.s.sol` asserts it stays unset). A ZK verifier implements `IAttestationVerifier.verify(digest, evidence)` for
the same `recordDigest` / `heartbeatDigest` and is enabled with `setVerifier(2, verifier)` alone; records then
carry `method = 2`. `test/ZkMethod.t.sol` plugs in a mock method-2 verifier with no other change and mixes
methods across registration and heartbeats. The mock only tests that plumbing: a real TDX quote cannot commit to
`recordDigest` (it contains `sha256(quote)`), and today's evidence report_data binds neither customer, deploymentId
nor time. Method 2 needs a report_data v2 binding first (contract review, crypto-SEAL-03).

## Build and test

```bash
make deps          # forge soldeer install (from soldeer.lock)
make build
make test          # 386 tests, no network: unit, fuzz (256 runs), invariants (128 runs x depth 64), scripts, audit
make test-ci       # FOUNDRY_PROFILE=ci: fuzz 1000 runs, invariants 256 runs x depth 100
make test-invariant-deep  # FOUNDRY_PROFILE=deep: invariants 1000 runs x depth 256, seed 0x5ea1ed, 2 threads
make test-fork     # 13 tests against Tempo mainnet (TEMPO_RPC_URL or https://rpc.tempo.xyz)
make local-e2e     # anvil --network tempo, deploy, full flow with cast
make catalog-check     # catalog/catalog.mainnet.json against ../catalog/apps/*/manifest.yaml
make rehearse-catalog  # register the mainnet catalog on a local node in the mainnet command shape
make coverage      # src/: 100% lines, statements, branches and functions
make gas-report
make abi           # abi/*.json
```

Tests run in `network = "tempo"` mode with `hardfork = "tempo:t12"`, so the TIP-20 precompiles exist and storage
writes cost the Tempo mainnet 250,000 gas per new slot. Invariants use `fail_on_revert = true` (handlers never
revert). Suites:

| Suite | Tests |
|---|---|
| `test/OracleSignatureVerifier.t.sol` | 29: signer management, every malformed-evidence case (length, offset, padding, high-s, bad v, raw sig, re-hashed digest), fuzz: never reverts |
| `test/PlatformRegistry.t.sol` | 29: add / deprecate / revoke and every revert, measurement lengths and uniqueness, fuzzed hash |
| `test/AppRegistry.t.sol` | 63: roles (AccessControl lockout), apps, releases (version and bundle uniqueness), D-013 status matrix, latestRelease |
| `test/DeploymentRegistry.t.sol` | 113: approvals (fixed content, re-approval rules), expiry, revocations, registration and heartbeat checks (attested before approval, quote reuse), close, admin, fuzzed freshness window, approval boundary and release count |
| `test/DeploymentRegistryEIP712.t.sol` | 14: typehashes, domain, hand-rolled digests (fuzzed), vm.sign with a generated oracle key, cross-chain and cross-contract replay, cast vector |
| `test/ZkMethod.t.sol` | 7: method 2 unset, pluggable, coexisting with method 1 |
| `test/FeeSplitter.t.sol` | 78: payments, top-ups of short legs (retry safety, caps, daily cap, exact approval, reentrancy), per-deployment usage keys, caps, day rollover, fee-on-transfer, reentrancy, withdraw, sweep, admin (treasury and registry checks); fuzzed split math (payments and top-ups) and caps |
| `test/invariant/*` | 33 invariants in 7 campaigns plus 6 handler sanity tests (forge counts each campaign as one test). FeeSplitter (7): credits == total == balance, ghost flows, daily cap, exact withdrawals, each leg's usagePaid == what payFees and topUpFees pulled. Approval (4): isStackApproved and approveStack outcomes equal an independent model; never true after revoke / expiry / release revoke / image revoke. FeeSplitterTip20 (4): real TIP-20 precompile tokens with TIP-403 blacklists and pauses; each payment credits exactly the maintainer's floor share and the treasury's rest and nothing else, no credit owed to an address that cannot withdraw, a payment or withdrawal stopped by `PolicyForbids` / `ContractPaused` changes nothing and can be retried. Lifecycle (7): DeploymentRegistry as a state machine with the real verifier and FeeSplitter; Active only after a verified record of a then-approved stack, Closed and revocations final, no heartbeat on an unapproved stack, usage legs never overlap across deployments. Catalog (5): every AppRegistry and PlatformRegistry call by every kind of caller against a model, state changes only through owner, registrar, maintainer or pending-owner paths, deactivated releases and debug or deactivated images never approvable. OracleVerifier (5): verify follows the current signer set (removal takes effect for old evidence), high-s, wrong-v and non-canonical evidence never verify. Stranger (1): callers without a role change nothing in any of the five contracts |
| `test/script/Scripts.t.sol` | 9: Deploy, RegisterCatalog (idempotent, appId check, `_pending` refused before sending), Transfer/AcceptOwnership in-process |
| `test/script/CatalogMainnet.t.sol` | 2: pins every field of `catalog/catalog.mainnet.json` and registers it on a fresh deployment |
| `test/Integration.t.sol` | 1: whole lifecycle including an incident revoke |
| `test/audit/*` | 27: every PoC of the contract review replayed; fixed findings assert the fix, acknowledged ones pin the documented behavior |
| `test/fork/TempoMainnetFork.t.sol` | 8: real pathUSD and USDC.e through FeeSplitter, TIP-403 checks |
| `test/fork/DeployedContractsFork.t.sol` | 5: the deployed mainnet contracts: runtime code equals this source built with the recorded constructor arguments, configuration equals `deployments/tempo-mainnet.json`, pure helpers agree with a fresh build (fuzzed), live solvency and catalog sanity, and a 54-step lifecycle with the same outcome on the deployed contracts and on a fresh build |

### Fork tests

`test/fork/TempoMainnetFork.t.sol` forks chain 4217 (`TEMPO_RPC_URL`, else `https://rpc.tempo.xyz`), deploys all
five contracts, and moves real pathUSD and USDC.e (the mainnet FEE_TOKEN, D-035): `approve` + `payFees`
(`transferFrom` into FeeSplitter) + `withdraw` (`transfer` out), enclave-signer payment, heartbeat and close. Test
accounts are funded by impersonating the Stablecoin DEX precompile (`0xDEc0…`, the largest pathUSD and USDC.e
holder), so balances and `totalSupply` stay consistent.
Every test is skipped (not failed) when the RPC is unreachable or `SKIP_FORK_TESTS=true`.

`test/fork/DeployedContractsFork.t.sol` checks the contracts at the addresses in `deployments/tempo-mainnet.json`.
It runs this source's creation code with the recorded constructor arguments at each deployed address (so the EIP-712
immutables match) and requires the result to equal the code on mainnet byte for byte, metadata hash included. It
then impersonates OWNER and ops on the local fork and runs the same scenario on the deployed contracts and on a
fresh build from a state snapshot, comparing the success flag and return or revert data of every step. Nothing is
sent to the network.

TIP-403: pathUSD uses policy 2, a BLACKLIST; freshly deployed contracts are authorized to send and receive. The
tests assert this for FeeSplitter and show the two failure modes: a blacklisted maintainer's `withdraw` reverts
`PolicyForbids` (credit and invariant intact), and a blacklisted payer cannot pay.

USDC.e uses policy 1 (always allow). Forks follow foundry.toml's `hardfork`, not the fork block, so the suite needs
Foundry 1.8.6 with `hardfork` at mainnet's: since T9 the token-to-policy binding lives in the TIP-403 registry, and
older rules read both policy ids as `0` (always reject). `setUp` requires pathUSD policy 2 and USDC.e policy 1 and
fails loudly otherwise; nothing is patched.

### Local Tempo node run

`script/local-e2e.sh` (or `make local-e2e`) starts `anvil --network tempo --hardfork T12 --gas-limit 500000000`
(`E2E_HARDFORK` to change it), deploys with `Deploy.s.sol` (`--broadcast`), records the deployment, registers two
apps and an image with `cast` and the fixture catalog (`test/fixtures/catalog.example.json`) with
`RegisterCatalog.s.sol`, publishes releases as ops, approves a stack as the
customer, registers a deployment with an oracle signature made by `cast wallet sign --no-hash`, heartbeats, pays
fees as customer and as enclave signer, tops up a leg the customer paid short, withdraws as maintainer and
treasury, pauses, closes and revokes a release, checking every result (including expected reverts and the
contract-review fixes: fixed approval content, unique measurements and bundles, quote reuse, per-deployment usage
keys, short legs topped up to the fee, treasury checks). It uses only anvil's public dev keys.

Local-node specifics handled by the script:
- The local genesis pre-deploys pathUSD, AlphaUSD, BetaUSD and ThetaUSD and gives every dev account `u64::MAX` of
  each, so no funding step is needed. On a fresh account use a dev-account transfer instead.
- Every transaction sets `--tempo.fee-token` AlphaUSD (a Tempo 0x76 transaction), so gas never touches pathUSD and
  all pathUSD deltas are asserted exactly. Without it, accounts 3..9 pay gas in pathUSD.
- `--gas-limit 500000000` (mainnet's block gas limit): anvil defaults to 30M. DeploymentRegistry's CREATE takes
  ~12M gas and forge adds a 1.3x estimate margin. The local deploy uses 41.72M gas (mainnet: 41.47M; a fresh dev
  account pays 250,000 more for its first transaction).

## Deploy to Tempo mainnet

Environment (from the workspace `.env`, `SEALED_ENV` to override; never printed):

| Variable | Use |
|---|---|
| `OWNER_PRIVATE_KEY` | deployer and owner of all five contracts (needs pathUSD for fees) |
| `OPS_ADDRESS` or `OPS_PRIVATE_KEY` | REGISTRAR_ROLE holder (address derived from the key if no address) |
| `ORACLE_ADDRESS` | oracle signer for method 1 |
| `TREASURY_ADDRESS` | FeeSplitter treasury |
| `FEE_TOKEN_ADDRESS` | default pathUSD `0x20c0000000000000000000000000000000000000` |
| `PER_PAYMENT_CAP`, `PER_DEPLOYMENT_DAILY_CAP` | defaults 5000000 and 20000000 |
| `TEMPO_RPC_URL` | default `https://rpc.tempo.xyz` |

```bash
make estimate-mainnet          # read-only eth_estimateGas for each CREATE
make deploy-mainnet            # dry run: simulates, writes deployments/tempo-mainnet.dry-run.json, sends nothing
make deploy-mainnet BROADCAST=1  # sends; then record-deployment.sh fills tx hashes/blocks/gas/fees and make abi runs
make verify-mainnet            # forge verify-contract --verifier sourcify --verifier-url https://contracts.tempo.xyz
```

The broadcast uses `FOUNDRY_PROFILE=deploy --skip-simulation --slow`: standard EIP-1559 transactions (D-038; with
gas left to the node, a Tempo 0x76 contract creation is estimated with an empty `calls` list, which mainnet
rejects), each gas limit taken from the node's `eth_estimateGas` just before sending, after the previous
transaction is mined. The deploy profile simulates with Ethereum rules (FeeSplitter's dry run reads -81%), so never
take limits or costs from it; the default-profile dry run (`make deploy-mainnet`) is within 3% of mainnet for the
CREATEs but shows ~22k for each wiring call, because those are estimated before the contracts exist. Never use
`--batch` for this deploy (a Tempo batch allows one CREATE). `deployments/tempo-mainnet.json` holds chain id,
deployer, start block, per-contract address, constructor args, tx hash, block number and gas, every transaction
with its fee, the wired configuration and the compiler settings. Verification needs the same compiler settings
(0.8.38, osaka, 200 runs, no via-IR); `verify-mainnet` passes the recorded constructor args.

Order: PlatformRegistry, AppRegistry, OracleSignatureVerifier, DeploymentRegistry, FeeSplitter, then
`grantRegistrar(OPS)`, `addSigner(ORACLE)`, `setVerifier(1, OracleSignatureVerifier)`. The script asserts owners,
role, signer, method 1 set, method 2 unset, treasury and fee token before writing the file.

Cost (mainnet `eth_estimateGas`, 2026-10-28, after the contract-review fixes, base fee at the 6e8 attodollar/gas
floor; FeeSplitter's estimate uses a state override for the placeholder registry, see the Makefile):

| Contract | Gas |
|---|---|
| PlatformRegistry | 5,727,274 |
| AppRegistry | 10,383,069 |
| OracleSignatureVerifier | 3,117,473 |
| DeploymentRegistry | 12,166,190 |
| FeeSplitter | 9,079,491 |
| 3 wiring calls (mainnet gasUsed: 280,902 + 532,030 + 283,315) | 1,096,247 |
| **Total** | **~41.6M gas = ~$0.025 at the floor, ~$0.50 at the 1.2e10 cap** |

## Catalog

`catalog/catalog.mainnet.json` is the mainnet catalog: the six seed apps (llm-gateway, scraper, crm, coding-agent,
internal-tools, inference-relay), each with `appId = keccak256(slug)`, the manifest's `name` and
`upstream.license_spdx`, maintainer `0x500A40bAB57E5F58f9c50D33fF70C6EaaAB11Eb2` (MAINTAINER_DEFAULT_ADDRESS),
`maintainerShareBps` 2000 and metadataURI
`https://github.com/sealedtempo/sealed/blob/main/catalog/apps/<slug>/manifest.yaml`. `images` stays empty until the
production sealed-os build prints measured values. `test/fixtures/catalog.example.json` is only a test fixture.

slug, name and licenseSpdx are permanent once registered (AppRegistry has no setter for them); maintainer,
maintainerShareBps and metadataURI can be changed later by OWNER. Spec 6.8: OWNER registers from a local machine,
never from CI.

```bash
make catalog-check CATALOG_STRICT=1   # read only: the file against ../catalog/apps/*/manifest.yaml
make rehearse-catalog                 # the same registration on a local node: state checks, gas per transaction
# dry run against mainnet, then the broadcast (OWNER_PRIVATE_KEY exported in the shell from the workspace .env):
CATALOG_FILE=catalog/catalog.mainnet.json FOUNDRY_PROFILE=deploy \
  forge script script/RegisterCatalog.s.sol:RegisterCatalog --rpc-url tempo
CATALOG_FILE=catalog/catalog.mainnet.json FOUNDRY_PROFILE=deploy \
  forge script script/RegisterCatalog.s.sol:RegisterCatalog --rpc-url tempo --broadcast --skip-simulation --slow
```

`CATALOG_FILE` defaults to `catalog/catalog.mainnet.json`; forge reads catalogs only under `./catalog` and
`./test/fixtures`. The script refuses the whole file before sending anything when an app entry's `appId` is not
`keccak256(slug)` or the entry carries a `_pending` key; other keys starting with `_` are comments. `imageId`
defaults to `keccak256(abi.encode(name, version, measurementsHash))`. Existing images and apps are skipped, so a
re-run is safe. The deploy-profile dry run uses Ethereum gas rules (about 2.1M for the six apps instead of 14.1M),
so take costs from `make rehearse-catalog`: 14,145,400 gas at T12, $0.0085 at the 6e8 floor, $0.17 at the cap.
OWNER's fee token preference must be USDC.e (`make fee-token-pref KEY_VAR=OWNER_PRIVATE_KEY`, D-038). Releases are
published by the release CI with the ops key (`publishRelease`), not by this script.

## Moving ownership to a multisig

1. `OWNER_PRIVATE_KEY=... NEW_OWNER=<safe> forge script script/TransferOwnership.s.sol:TransferOwnership --rpc-url
   tempo --broadcast --skip-simulation --slow` calls `transferOwnership(safe)` on all five contracts. Nothing
   changes yet; OWNER keeps control and can re-point the transfer.
2. The Safe calls `acceptOwnership()` (selector `0x79ba5097`, no arguments) on each of the five addresses, for
   example as one Transaction Builder batch. For an EOA new owner: `NEW_OWNER_PRIVATE_KEY=... forge script
   script/TransferOwnership.s.sol:AcceptOwnership ...`.
3. Check `owner()` on each. REGISTRAR_ROLE, oracle signers and FeeSplitter credits are unaffected; the new owner
   manages the registrar through `grantRegistrar` / `revokeRegistrar`.

## Tempo notes

- No native token: nothing is `payable`; `msg.value` and balances are always 0. Fees are paid in TIP-20 USD tokens.
  Calls to these contracts pay fees in pathUSD by default (fee token fallback), so OWNER, OPS, customers and
  enclave signers need pathUSD (or another USD TIP-20 via the fee-token field or `FeeManager.setUserToken`).
- Gas: every new storage slot costs 250,000 gas, contract creation 500,000 + 1,000 per deployed byte, at most 30M
  gas per transaction. At the base-fee floor (6e8 attodollars/gas) 1M gas costs $0.0006. Typical calls on the
  Tempo schedule (gas report, T12, medians unless noted): `registerDeployment` 2.6M (max), `approveStack` 1.3M
  (2 releases), `publishRelease` 2.8M, `registerApp` 2.3M with the mainnet catalog's strings, `addImage` 2.3M,
  `payFees` 0.62M (1.9M max, a deployment's first payment), `topUpFees` 0.12M, `withdraw` 0.31M, `heartbeat` 62k.
  The gas report's "Deployment Cost" column reads 0 on `network = "tempo"`; use `make estimate-mainnet`.
- TIP-20 transfers revert (not return false) on failure and return true on success, so SafeERC20 works. Recipients
  `address(0)` and `0x20c0…`-prefixed token addresses are rejected by the token.
- TIP-403 policy 2 on pathUSD is a blacklist: a blacklisted payer cannot pay, a blacklisted maintainer or treasury
  cannot withdraw (its credit stays frozen); the policy admin can also blacklist our contracts.
- Receive policies (T6) can redirect an inbound transfer to the ReceivePolicyGuard without reverting; payFees'
  balance-delta check rejects such a payment. A withdrawal to an account that set a receive policy rejecting
  FeeSplitter lands in the guard (`0xB10C…`) and is recovered under that account's recovery-authority rules.
- Blocks are ~0.5 s and consecutive blocks can share `block.timestamp`; nothing here uses it for uniqueness.
- Foundry 1.8.6 knows Tempo hardforks T0 to T14 and does not follow the activation schedule: forks, tests and
  anvil run whatever `hardfork` says (anvil's default is T12). Mainnet activates T13 on 2026-11-03 15:00 UTC; then
  change `hardfork` to `"tempo:t13"` and the `E2E_HARDFORK` / `REHEARSE_HARDFORK` defaults to T13. Older Foundry
  releases run T4 rules (policy ids read as 0, CREATE gas ~2.3x mainnet), which `make foundry-check` rejects.
- `forge-std` `deal()` still fails for TIP-20 tokens on 1.8.6; unit tests use mock tokens and the fork tests fund
  by impersonation.
