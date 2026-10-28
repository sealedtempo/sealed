# Upgrading deployment records to ZK proofs (attestation method 2)

Today every onchain deployment record is accepted on the signature of the platform's oracle key (method 1, `ORACLE_SIG_V1`). Method 2 (`ZK_DCAP_V1`) replaces that signature with a succinct proof that an Intel DCAP verification of the deployment's TDX quote succeeded, checked by a contract on Tempo. This document covers deploying Automata's DCAP attestation contracts on Tempo, proving TDX quotes with SP1 or RISC Zero, implementing `IAttestationVerifier` for method 2 with the prerequisites from the contract review, and switching new records to it with no change to the deployed contracts.

What a proof shows, and what it does not: it shows that a computation verified a quote against Intel's collateral and that the quote binds the record. It does not show anything about what the apps do with data. Confidential VMs do not stop physical attacks on the server, bugs inside apps, or a cloud provider with physical access.

Method 2 does not touch the secret-release path. The customer's key broker verifies quotes itself and never reads deployment records.

## Where the contracts stand

- `DeploymentRegistry` (`0x254eFB9d1809A95Ec6d233cC57b3a10849bd2C8E`) keeps one verifier per method id (`verifiers(uint8)`). `registerDeployment(Record r, uint8 method, bytes evidence)` and `heartbeat(deploymentId, quoteHash, attestedAt, method, evidence)` call `verifiers[method].verify(digest, evidence)`, where the digest is `recordDigest(r)` or `heartbeatDigest(deploymentId, quoteHash, attestedAt)` (EIP-712, domain `Sealed DeploymentRegistry`, version 1, chain 4217).
- `IAttestationVerifier` is `function verify(bytes32 recordDigest, bytes calldata evidence) external view returns (bool)`. Implementations must not re-hash the digest and should return false rather than revert.
- Method 1 is `OracleSignatureVerifier` at `0xf680E602758222d5aE1CcD797a03022bCE2dd353`. Method 2 is reserved and unset: `Deploy.s.sol` asserts it, and `contracts/deployments/tempo-mainnet.json` records `verifierMethod2` as the zero address.
- `setVerifier(method, address)` is owner-only, refuses method 0 and addresses without code, and `address(0)` unsets a method.
- The registry still runs its own checks for every method: the stack is approved, the record's image is the approval's image, `attestedAt` is at most 5 minutes in the future and within `maxAttestationAge` (1 day), the record is attested after the approval (`AttestedBeforeApproval`), and a heartbeat brings a new quote (`QuoteReused`).
- `contracts/test/ZkMethod.t.sol` plugs a mock into method 2 with no other change, mixes methods across registration and heartbeats, unplugs it, and disables method 1 while method 2 keeps working. The mock (`MockZkDcapVerifier`) tests only that plumbing.

## Prerequisites before `setVerifier(2, ...)` (contract review crypto-SEAL-03)

### Why the current evidence is not enough

1. A TDX quote cannot commit to `recordDigest`: the Record contains `quoteHash = sha256(quote)`, so the digest exists only after the quote.
2. The evidence report_data (`sealed/evidence/v1`, D-047) binds stackHash, configHash, enclaveSigner, nonce2 and attestedAt, but not the deploymentId or the customer, and attestedAt is the VM's own clock. With the oracle, the platform checks those offchain (it recomputes the deploymentId from the config and checks freshness within 15 minutes). A contract has no such context.

### report_data v2

A new evidence construction, used only for method-2 evidence (the key-release and live-attest constructions stay as they are):

```
report_data = sha256("sealed/evidence/v2"
                     || deploymentId[32] || customer[20] || stackHash[32] || configHash[32] || imageId[32]
                     || enclaveSigner[20] || anchorBlockNumber[uint64be] || anchorBlockHash[32]
                     || nonce2[32] || attestedAt[uint64be])
              || 32 zero bytes
```

- `anchorBlockNumber` and `anchorBlockHash` are a recent Tempo block the agent reads from its RPC (already on its egress allowlist) just before it asks for the quote. The verifier checks the hash with `blockhash()` for the last 256 blocks, or with the EIP-2935 history contract for a longer window. This gives a chain-anchored lower bound on when the quote was made, independent of the VM's clock. Size the window to Tempo's block time, and confirm EIP-2935 on Tempo before relying on it.
- Binding the deploymentId, the customer and the configHash lets the contract check what the oracle checks today, and lets it recompute `deploymentId = keccak256(abi.encode(customer, stackHash, salt))` from a salt carried in the evidence (closing crypto-SEAL-04 for method 2).
- The review also allows in-circuit parsing of the config instead. Prefer report_data v2: then the prover only ever sees the quote, never the public config, which carries the VM's address.
- This is a format change: record it as a decision, add it to `docs/INTERFACES.md` section 3, build it in `@sealed/core` and the agent, and teach `verifier/attest` and `sealed verify`. The agent is part of every stack, so stacks produce v2 evidence only after they move to an agent image and composer version that emit it, which means a new stackHash and a new approval by the customer.

### RTMR3 and the compose hash

A DCAP proof covers the quote. It does not replay dstack's event log, but the record's stackHash is only meaningful if RTMR3 replays to a `compose-hash` event equal to it ([THREAT_MODEL.md](THREAT_MODEL.md#rtmr3-and-the-compose-hash)). Two ways:

- Onchain replay: the evidence carries the RTMR3 event log (about ten short events, all public hashes), and the verifier recomputes `sha384(le32(0x08000001) || ":" || name || ":" || payload)` and the fold in Solidity. SHA-384 has no EVM precompile, so this is expensive; do it once per quote in the submission step below, not in every `verify` call.
- In the proof: a Sealed guest program that runs Automata's DCAP verification (`dcap-rs`), the RTMR3 replay and the report_data v2 check, and outputs a compact journal. Cheaper onchain, but a new program to review and pin, and the verifier must then check the collateral the journal names against the onchain PCCS itself.

Start with onchain replay: it reuses Automata's audited program and contracts unchanged.

### quoteHash for method-2 records

`Record.quoteHash` is `sha256(raw quote)` today. Under method 2 the raw quote should not go onchain (it carries the PCK certificate chain, which identifies the host platform; P6 keeps records to hashes and addresses). Either the proven output commits to `sha256(raw quote)` (the guest-program route), or method-2 records define quoteHash as the hash of the verified output. Decide before implementation and document it; the contract stores quoteHash opaquely and only requires a new one per heartbeat.

## Deploying Automata's DCAP attestation contracts on Tempo

[automata-dcap-attestation](https://github.com/automata-network/automata-dcap-attestation) (MIT) holds the EVM contracts and the Rust crates:

- `PCCSRouter`: reads collateral (Intel root CA, CRLs, QE identity, TCB info) from [automata-on-chain-pccs](https://github.com/automata-network/automata-on-chain-pccs).
- The attestation entrypoint, `AutomataDcapAttestationFee`, which routes to a quote verifier per quote version (V3, V4, V5). TDX quotes are version 4 or 5, and Sealed's verifier library accepts both.
- `verifyAndAttestOnChain(bytes calldata rawQuote)` verifies a whole quote onchain. `verifyAndAttestWithZKProof(bytes calldata output, ZkCoProcessorType zkCoprocessor, bytes calldata proofBytes)` verifies a zkVM proof of the same verification, with variants that also take a `programIdentifier` and a `tcbEvaluationDataNumber`. All are `external payable` with a fee modifier; none is `view`.
- Rust crates: `dcap-rs` (DCAP verification for SGX and TDX quotes), `zkvm` (proof generation), `pccs-reader`, and the `automata-dcap` CLI for verification, collateral detection and proof generation. The older `automata-dcap-zkvm-cli` repository is archived; use the monorepo.

Steps:

1. Pin a commit of both repositories and record it, with licenses, in the build notes (rule 10). Check Automata's network registry for an existing Tempo deployment; assume none.
2. Rehearse on `anvil --network tempo` and on a fork of Tempo mainnet. Confirm the precompiles the contracts need (SHA-256 at `0x02`, BN254 `ecAdd`, `ecMul` and `ecPairing` at `0x06` to `0x08` for Groth16 and Plonk verification, and P-256 verification at `0x100` if the onchain path is used), contract size limits and gas. Tempo executes the Osaka EVM, but every assumption is checked on the fork first.
3. Deploy the PCCS, the router, the entrypoint and the V4 and V5 quote verifiers with Automata's targets (`make deploy-router`, `make deploy-attestation`, `make deploy-verifier QUOTE_VERIFIER_VERSION=4` and `5`, `make config-verifier`, `make config-router CALLER_ADDRESS=<our verifier> AUTHORIZED=true`). On Tempo with Foundry 1.7.1, contract creations must go out as standard EIP-1559 transactions after the sender's fee token preference is set (`FeeManager.setUserToken`, D-038), exactly as the five Sealed contracts were deployed. Every transaction pays its network fee in USDC.e, and every one goes into the mainnet ledger.
4. Fees: Tempo has no native token, so a fee paid through `msg.value` cannot exist. Set our instance's fee to zero (`setBp(0)`) and test that the fee modifier passes with zero value.
5. Collateral: load Intel's root CA, the CRLs, the TDX QE identity and the TCB info for the FMSPCs of Google Cloud C3 hosts from Intel PCS into the onchain PCCS. Intel re-signs and replaces them on a schedule, so a job must refresh them before they expire, or proofs start failing. The collateral is Intel-signed and checked when it is loaded, so the uploader affects availability, not authenticity.
6. zkVM verifier: deploy the RISC Zero verifier router ([risc0-ethereum](https://github.com/risc0/risc0-ethereum)) or the SP1 verifier gateway ([sp1-contracts](https://github.com/succinctlabs/sp1-contracts)) on Tempo, then point the entrypoint at it and at the DCAP program's identifier (the RISC Zero image id or the SP1 verification key) with `make config-zk ZKVM_SELECTOR=<n> ZKVM_VERIFIER_ADDRESS=<address> ZKVM_PROGRAM_IDENTIFIER=<id>`.
7. Verify every source at https://contracts.tempo.xyz and record the addresses in a separate deployments file (for example `contracts/deployments/tempo-mainnet-zk.json`), leaving the five core contracts' file as it is.

## Proving TDX quotes with SP1 or RISC Zero

- Inputs: the raw quote from the evidence bundle and its collateral (from Intel PCS, a local PCCS, or the onchain PCCS). The prover learns the measurements, report_data (a hash) and the platform's PCK certificate chain; never secrets, app data or the config.
- RISC Zero: Groth16 proofs through Bonsai or Boundless. SP1: Groth16 or Plonk proofs through the SP1 network. Pico: local proving only. Automata's CLI produces the verified output and the proof bytes that `verifyAndAttestWithZKProof` takes.
- Anyone can prove and submit, because `registerDeployment` and `heartbeat` are permissionless and the evidence is what authorizes them. The platform runs a prover in place of the oracle signature; a customer can prove its own deployment.
- Proving takes minutes. Registrations have a day (`maxAttestationAge`) and heartbeats come every 24 hours, so latency is not a constraint; freshness comes from the anchor block in report_data v2.

## Implementing `IAttestationVerifier` for method 2

`verify` must be `view`, and Automata's ZK entrypoint is not. So the method-2 verifier (for example `SealedZkDcapVerifierV1`, non-upgradeable, owned like the others) has two entry points:

1. `submitQuote(output, zkCoprocessor, proofBytes, eventLog)`, callable by anyone: calls `verifyAndAttestWithZKProof`; on success parses the TD report body from the verified output, replays RTMR3 from `eventLog` against the quote's RTMR3, and stores, keyed by a quote id, the facts later checks need: TCB status, TD_ATTRIBUTES, `measurementsHash = keccak256(mrtd || rtmr0 || rtmr1 || rtmr2)`, report_data, the compose hash and the eventLogHash. Statuses outside the TCB policy (`UpToDate`, `SWHardeningNeeded`) are refused here.
2. `verify(recordDigest, evidence)`, view: decodes `evidence = abi.encode(kind, fields, salt, anchorBlockNumber, anchorBlockHash, nonce2, quoteId)` and returns true only when:
   - for a Record: the Record rebuilt from `fields` gives `DeploymentRegistry.recordDigest(r) == recordDigest`; for a Heartbeat: `heartbeatDigest(deploymentId, quoteHash, attestedAt) == recordDigest`, and the deployment's stored customer, stackHash, imageId, configHash and enclaveSigner (`getDeployment`) are used as the fields;
   - the stored quote facts exist; TD_ATTRIBUTES has no debug, migratable or reserved bits;
   - `measurementsHash == PlatformRegistry.getImage(imageId).measurementsHash`, the image is approved and not a debug image;
   - the stored compose hash equals the stackHash, and the stored eventLogHash equals the record's;
   - the stored report_data equals the v2 construction over the record's fields, the anchor and nonce2;
   - `blockhash(anchorBlockNumber) == anchorBlockHash` (or the EIP-2935 history), within the window;
   - `keccak256(abi.encode(customer, stackHash, salt)) == deploymentId`;
   - the record's quoteHash matches the quote id under the rule chosen above.

   Any mismatch returns false.

Tests before mainnet:

- Replace `MockZkDcapVerifier` with a mock that models these checks (the review's last prerequisite), and keep every `ZkMethod.t.sol` case: mixing methods, unplugging method 2, disabling method 1.
- Unit and fuzz tests for every false path above, with real proofs of a real Google Cloud TDX quote on the Tempo fork, and the tamper cases of `verifier/cmd/sealed-verifierd/compose_e2e_test.go` repeated against the contract.
- A fresh security review of the verifier, as for the five core contracts.

## Switching new records to method 2

No change to PlatformRegistry, AppRegistry, DeploymentRegistry, OracleSignatureVerifier or FeeSplitter.

1. Deploy and verify the method-2 verifier and its dependencies as above.
2. The owner calls `DeploymentRegistry.setVerifier(2, <method-2 verifier>)`. The `VerifierSet` event records it.
3. Release an agent and composer version that emit report_data v2 evidence. New stacks use it; existing stacks move when their customers approve the new stack.
4. The submitter proves each new deployment's quote, calls `submitQuote`, then `registerDeployment(r, 2, evidence)`, and later `heartbeat(deploymentId, quoteHash, attestedAt, 2, evidence)`. A deployment registered under method 1 may send method-2 heartbeats once its agent emits v2 evidence; `getDeployment` shows `method` (registration) and `lastMethod` (latest heartbeat).
5. `sealed verify`, the indexer and the console report the method and check method-2 evidence with the v2 construction. Method-1 records remain valid history.
6. When no Active deployment relies on oracle heartbeats any more, retire the oracle: `OracleSignatureVerifier.removeSigner(<oracle>)` or `setVerifier(1, address(0))`. From then on, no onchain record depends on a platform key.
7. Rollback at any time: `setVerifier(2, address(0))` stops new method-2 records; records already registered stay.

## What changes in the trust model

| | method 1 | method 2 |
|---|---|---|
| who vouches for a record | the oracle key, after the platform verified the evidence offchain | Intel's root of trust and collateral, checked by a zkVM proof and by contracts on Tempo |
| new anchors | none | Automata's contracts and their owner's configuration, the zkVM verifier contract and the DCAP program identifier, the soundness of the proof system, collateral freshness (availability) |
| removed anchors | none | the oracle key, for method-2 records |
| unchanged | secret release by the customer's key broker; stack recomputation offchain (the customer's approval of the stackHash already covers the composition onchain); the limits of confidential VMs | same |
