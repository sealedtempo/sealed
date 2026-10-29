// Package keybroker releases a customer's secrets to attested Sealed stacks that the customer approved onchain
// (spec 5.7, INTERFACES.md section 9, D-011, D-012, D-014, D-042, D-043, D-046, D-047, D-058, D-059, D-060, D-066).
//
// The broker runs on Cloud Run in the customer's own project. GET /v1/nonce hands out single-use 32-byte nonces.
// POST /v1/release runs every check in a fixed order and stops at the first failure:
//
//  1. nonce: known, unused, younger than five minutes (bad_nonce), then the request is validated (bad_request).
//     These run before a release slot is taken; their failures are junk, logged truncated in the background.
//  2. quote: a TDX quote whose PCK chain ends at the Intel SGX Root CA and that verifies with Intel collateral
//     (quote_invalid; 503 when Intel PCS cannot serve collateral) and an allowed TCB status (tcb_status); simulated
//     quotes only in dev builds and never on mainnet
//  3. report_data: sha256("sealed/kb-release/v1" || nonce || ephemeralPub) || 32 zero bytes (report_data_mismatch)
//  4. chain: the RPC serves the configured chain and its head block is at most 60 s (configurable, at most 300 s)
//     from the broker's clock (503 chain_stale); the image and release reads below are pinned to that block
//  5. image: PlatformRegistry.getImage(imageId) exists (image_not_approved), its measurementsHash equals the quote's
//     (measurements_mismatch), MRCONFIGID and MROWNERCONFIG are zero (measurements_mismatch), it is not a debug
//     image and the TD has no debug attributes (image_debug), isApprovedImage(imageId) and, when set, the
//     customer's own image allowlist (image_not_approved)
//  6. rtmr3: the event log replays to the quote's RTMR3 with the exact Sealed sequence (rtmr3_replay)
//  7. compose_hash: the compose-hash event equals sha256(appCompose) (compose_mismatch)
//  8. customer: config.customer is the bootstrap customer (customer_mismatch); config_chain: the config names this
//     broker's chain, registries, fee splitter and fee token (stack_not_approved)
//  9. stack_recompute: runtime/composer recomputes appCompose byte for byte from the config and the releases'
//     bundles, fetched by the release asset URL rule and checked against the onchain bundleHash
//     (bundle_hash_mismatch, compose_mismatch)
//  10. chain again: the approval and deployment reads are pinned to the current head, which must also be within the bound
//     (503 chain_stale), so the bundle fetches and the compose cannot age the approval read (kb-2)
//  11. stack_approved: DeploymentRegistry.isStackApproved(customer, stackHash) (stack_not_approved)
//  12. approval_releases: the approval's releaseIds equal config.apps[].releaseId as a set, and its imageId equals
//     config.imageId and the request's imageId (stack_not_approved)
//  13. deployment: DeploymentRegistry.getDeployment(deploymentId) is not Closed; a deployment that is not registered
//     yet (the first boot) passes (stack_not_approved)
//
// Only then does it read the secrets the stack's manifests name (same_as only where the source secret lists the
// referencing app in share_with), derive diskKey and signerSeed from (customer, salt) with the Cloud KMS HMAC key,
// and seal them to the ephemeral X25519 key with HPKE. Right before the seal the head of the approval reads must
// still be within the bound (503 chain_stale), so every mutable chain read (isStackApproved covers the image and
// release status) is at most MaxHeadAge old when the release is decided. Every decision, allowed or not, is written to the decision
// log with its reason, checks and hashes; an allowed release is only answered after its log entry was written.
package keybroker
