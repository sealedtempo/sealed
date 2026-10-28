// Package keybroker releases a customer's secrets to attested Sealed stacks that the customer approved onchain
// (spec 5.7, INTERFACES.md section 9, D-011, D-012, D-014, D-042, D-043, D-046, D-047).
//
// The broker runs on Cloud Run in the customer's own project. GET /v1/nonce hands out single-use 32-byte nonces.
// POST /v1/release runs every check in a fixed order and stops at the first failure:
//
//  1. nonce: known, unused, younger than five minutes (bad_nonce)
//  2. quote: a TDX quote that verifies with Intel collateral (quote_invalid) and an allowed TCB status
//     (tcb_status); simulated quotes only in dev builds
//  3. report_data: sha256("sealed/kb-release/v1" || nonce || ephemeralPub) || 32 zero bytes (report_data_mismatch)
//  4. image: PlatformRegistry.getImage(imageId) exists (image_not_approved), its measurementsHash equals the quote's
//     (measurements_mismatch), it is not a debug image and the TD has no debug attributes (image_debug), and
//     isApprovedImage(imageId) (image_not_approved)
//  5. rtmr3: the event log replays to the quote's RTMR3 with the exact Sealed sequence (rtmr3_replay)
//  6. compose_hash: the compose-hash event equals sha256(appCompose) (compose_mismatch)
//  7. stack_recompute: runtime/composer recomputes appCompose byte for byte from the config and the releases'
//     bundles, fetched by the release asset URL rule and checked against the onchain bundleHash
//     (bundle_hash_mismatch, compose_mismatch)
//  8. customer: config.customer is the bootstrap customer (customer_mismatch), on this broker's chain and registries
//     (stack_not_approved)
//  9. stack_approved: DeploymentRegistry.isStackApproved(customer, stackHash) (stack_not_approved)
//  10. approval_releases: the approval's releaseIds equal config.apps[].releaseId as a set, and its imageId equals
//     config.imageId and the request's imageId (stack_not_approved)
//
// Only then does it read the secrets the stack's manifests name (with same_as resolution) from Secret Manager,
// derive diskKey and signerSeed with the Cloud KMS HMAC key, and seal them to the ephemeral X25519 key with HPKE.
// Every decision, allowed or not, is written to the decision log with its reason, checks and hashes; an allowed
// release is only answered after its log entry was written.
package keybroker
