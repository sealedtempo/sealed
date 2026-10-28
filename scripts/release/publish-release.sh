#!/usr/bin/env bash
# Publish one catalog release on Tempo with AppRegistry.publishRelease, as OPS (REGISTRAR_ROLE).
#
#   scripts/release/publish-release.sh --info <bundle-info.json> --provenance-uri <url> --signature-uri <url> \
#     [--out <result.json>] [--dry-run]
#
# --info is the output of `catalog/tools/release bundle` or `info` (appId, slug, version, bundleHash,
# egressPolicyHash, sbomHash, releaseId). In order, the script:
#   1. checks the inputs (appId = keccak256(slug), releaseId = keccak256(abi.encode(appId, version, bundleHash)));
#   2. checks the RPC serves EXPECT_CHAIN_ID and AppRegistry has code;
#   3. refuses to run when the app is not registered (OWNER registers apps with register-apps.sh, never CI),
#      or when OPS lacks REGISTRAR_ROLE;
#   4. exits 0 without sending when this exact release is already published (re-runs are safe), and fails
#      when the version or the bundle is already published as another release;
#   5. ensures OPS's FeeManager fee token preference is FEE_TOKEN (D-038), sending setUserToken if needed;
#   6. simulates publishRelease with eth_call, then sends it as a Tempo transaction that pays its fee in
#      FEE_TOKEN (D-035), and checks the receipt, releaseByVersion and isActiveRelease afterwards;
#   7. writes the onchain record (tx hash, block, fee) to --out and prints a MAINNET_LEDGER.md row.
# --dry-run (or DRY_RUN=1) stops after the simulation; nothing is sent.
#
# Environment:
#   OPS_PRIVATE_KEY     the REGISTRAR key (GitHub secret in the mainnet environment; never printed)
#   TEMPO_RPC_URL       default: config/defaults.yaml chain.public_rpc_url
#   EXPECT_CHAIN_ID     default: config/defaults.yaml chain.chain_id (4217)
#   DEPLOYMENTS_FILE    default: contracts/deployments/tempo-mainnet.json
#   FEE_TOKEN_ADDRESS   default: the deployments file's config.feeToken, else chain.fee_token
#   LOG_LOOKBACK_BLOCKS how far back to search for the ReleasePublished event of an already published
#                       release (default 500000)
# Exit codes: 0 published or already published, 2 usage, 3 refused (app not registered, no role, conflict),
# 1 anything else.

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

usage() {
	sed -n '2,7p' "$0" >&2
	exit 2
}

INFO="" PROV="" SIGURI="" OUT=""
DRY_RUN="${DRY_RUN:-0}"
while [ $# -gt 0 ]; do
	case "$1" in
	--info) INFO="${2:-}"; shift 2 ;;
	--provenance-uri) PROV="${2:-}"; shift 2 ;;
	--signature-uri) SIGURI="${2:-}"; shift 2 ;;
	--out) OUT="${2:-}"; shift 2 ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help) usage ;;
	*) log "unknown argument: $1"; usage ;;
	esac
done
[ -n "$INFO" ] && [ -f "$INFO" ] || usage
[[ "$PROV" =~ ^https:// ]] || die "--provenance-uri must be an https URL" 2
[[ "$SIGURI" =~ ^https:// ]] || die "--signature-uri must be an https URL" 2
need cast
need jq

RPC="${TEMPO_RPC_URL:-$(defaults_get publicRpcUrl)}"
EXPECT_CHAIN_ID="${EXPECT_CHAIN_ID:-$(defaults_get chainId)}"
DEPLOYMENTS_FILE="${DEPLOYMENTS_FILE:-$RELEASE_ROOT/contracts/deployments/tempo-mainnet.json}"
[ -f "$DEPLOYMENTS_FILE" ] || die "deployments file $DEPLOYMENTS_FILE not found"
FEE_TOKEN="${FEE_TOKEN_ADDRESS:-$(jq -r '.config.feeToken // empty' "$DEPLOYMENTS_FILE")}"
FEE_TOKEN="${FEE_TOKEN:-$(defaults_get feeToken)}"
[[ "$FEE_TOKEN" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "no fee token address"
FEE_TOKEN="$(printf '%s' "$FEE_TOKEN" | lower)"

# 1. Inputs.
field() {
	local v
	v="$(jq -r --arg k "$1" '.[$k] // empty' "$INFO")"
	[ -n "$v" ] || die "$INFO has no $1" 2
	printf '%s' "$v"
}
SLUG="$(field slug)"
VERSION="$(field version)"
APP_ID="$(field appId | lower)"
BUNDLE_HASH="$(field bundleHash | lower)"
EGRESS_HASH="$(field egressPolicyHash | lower)"
SBOM_HASH="$(field sbomHash | lower)"
RELEASE_ID="$(field releaseId | lower)"
for h in "$APP_ID" "$BUNDLE_HASH" "$EGRESS_HASH" "$SBOM_HASH" "$RELEASE_ID"; do
	[[ "$h" =~ ^0x[0-9a-f]{64}$ ]] || die "$INFO: $h is not a 32-byte hex value" 2
done
[ "$BUNDLE_HASH" != "0x$(printf '0%.0s' {1..64})" ] || die "bundleHash is zero" 2
[ "$(cast keccak "$SLUG")" = "$APP_ID" ] || die "appId is not keccak256(\"$SLUG\")" 2
want_release="$(cast keccak "$(cast abi-encode 'f(bytes32,string,bytes32)' "$APP_ID" "$VERSION" "$BUNDLE_HASH")")"
[ "$want_release" = "$RELEASE_ID" ] || die "releaseId is not keccak256(abi.encode(appId, version, bundleHash))" 2
log "release $SLUG $VERSION: releaseId $RELEASE_ID, bundleHash $BUNDLE_HASH"

# 2. Chain and contract.
check_chain
REGISTRY="$(deployments_addr AppRegistry)"
require_code "$REGISTRY" AppRegistry
make_keystore OPS_PRIVATE_KEY
OPS="$KS_ADDR"
log "ok   chain $CHAIN_ID, AppRegistry $REGISTRY, OPS $OPS"

# 3. Refusals.
if [ "$(ccall "$REGISTRY" 'appExists(bytes32)(bool)' "$APP_ID")" != "true" ]; then
	die "refusing to publish: app $SLUG ($APP_ID) is not registered in AppRegistry; OWNER runs scripts/release/register-apps.sh first" 3
fi
if [ "$(ccall "$REGISTRY" 'hasRole(bytes32,address)(bool)' "$REGISTRAR_ROLE" "$OPS")" != "true" ]; then
	die "refusing to publish: $OPS does not hold REGISTRAR_ROLE on AppRegistry" 3
fi
log "ok   $SLUG is registered and OPS holds REGISTRAR_ROLE"

write_result() { # write_result <receipt.json> <alreadyPublished>
	local ts summary
	ts="$(cast block "$(jq -r .blockNumber "$1")" -f timestamp --rpc-url "$RPC")"
	summary="$(release_tool tx-summary --receipt "$1" --chain-id "$CHAIN_ID" --to "$REGISTRY" --release-id "$RELEASE_ID" \
		--from-label OPS --to-label AppRegistry --purpose "publishRelease $SLUG $VERSION" --timestamp "$ts")"
	if [ -n "$OUT" ]; then
		jq --argjson already "$2" '.record + {alreadyPublished: $already}' <<<"$summary" >"$OUT"
	fi
	jq -r '.record | "tx \(.txHash) block \(.blockNumber) fee \(.feeUsd) USD"' <<<"$summary" >&2
	printf 'MAINNET_LEDGER.md row:\n%s\n' "$(jq -r .ledger <<<"$summary")" >&2
}

# 4. Idempotency and conflicts.
by_version="$(ccall "$REGISTRY" 'releaseByVersion(bytes32,string)(bytes32)' "$APP_ID" "$VERSION" | lower)"
by_bundle="$(ccall "$REGISTRY" 'releaseByBundle(bytes32,bytes32)(bytes32)' "$APP_ID" "$BUNDLE_HASH" | lower)"
zero="0x$(printf '0%.0s' {1..64})"
if [ "$by_version" = "$RELEASE_ID" ]; then
	log "ok   $SLUG $VERSION is already published as $RELEASE_ID; nothing to send"
	head="$(cast block-number --rpc-url "$RPC")"
	from_block="$(jq -r '.contracts.AppRegistry.blockNumber // 0' "$DEPLOYMENTS_FILE")"
	lookback="${LOG_LOOKBACK_BLOCKS:-500000}"
	[ "$((head - lookback))" -gt "$from_block" ] && from_block="$((head - lookback))"
	tx="$(cast logs --rpc-url "$RPC" --json --from-block "$from_block" --to-block latest --address "$REGISTRY" \
		'ReleasePublished(bytes32 indexed,bytes32 indexed,address indexed,string,bytes32,bytes32,bytes32,string,string)' \
		"$RELEASE_ID" 2>/dev/null | jq -r '.[0].transactionHash // empty' || true)"
	if [ -z "$tx" ]; then
		die "already published, but the ReleasePublished event of $RELEASE_ID is not within $lookback blocks; raise LOG_LOOKBACK_BLOCKS" 1
	fi
	receipt="$(mktemp)"
	add_cleanup "rm -f '$receipt'"
	cast receipt "$tx" --json --rpc-url "$RPC" >"$receipt"
	write_result "$receipt" true
	exit 0
fi
if [ "$by_version" != "$zero" ]; then
	die "refusing to publish: $SLUG $VERSION is already published as release $by_version with another bundle; bump release_version" 3
fi
if [ "$by_bundle" != "$zero" ]; then
	die "refusing to publish: this bundle is already published as release $by_bundle under another version" 3
fi

# 5. Fee token preference.
ensure_fee_token "$OPS"
balance="$(ccall "$FEE_TOKEN" 'balanceOf(address)(uint256)' "$OPS" | awk '{print $1}')"
[ "$balance" != "0" ] || die "OPS holds no fee token ($FEE_TOKEN) to pay the fee"

# 6. Simulate, then send.
SIG='publishRelease(bytes32,string,bytes32,bytes32,bytes32,string,string)'
ARGS=("$APP_ID" "$VERSION" "$BUNDLE_HASH" "$EGRESS_HASH" "$SBOM_HASH" "$PROV" "$SIGURI")
sim="$(ccall --from "$OPS" "$REGISTRY" "$SIG(bytes32)" "${ARGS[@]}" 2>&1)" || die "publishRelease simulation reverted: $sim"
[ "$(printf '%s' "$sim" | lower)" = "$RELEASE_ID" ] || die "publishRelease simulation returned $sim, expected $RELEASE_ID"
log "ok   simulation returns releaseId $RELEASE_ID"
if [ "$DRY_RUN" = 1 ]; then
	log "dry run: publishRelease not sent"
	exit 0
fi
receipt="$(mktemp)"
add_cleanup "rm -f '$receipt'"
csend "$REGISTRY" "$SIG" "${ARGS[@]}" >"$receipt" || die "publishRelease could not be sent"
[ "$(jq -r .status "$receipt")" = "0x1" ] || die "publishRelease reverted (tx $(jq -r .transactionHash "$receipt"))"
[ "$(ccall "$REGISTRY" 'releaseByVersion(bytes32,string)(bytes32)' "$APP_ID" "$VERSION" | lower)" = "$RELEASE_ID" ] ||
	die "releaseByVersion does not return $RELEASE_ID after the transaction"
[ "$(ccall "$REGISTRY" 'isActiveRelease(bytes32)(bool)' "$RELEASE_ID")" = "true" ] || die "release $RELEASE_ID is not active"
log "ok   published $SLUG $VERSION"

# 7. Record.
write_result "$receipt" false
