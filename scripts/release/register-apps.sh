#!/usr/bin/env bash
# Register catalog apps in AppRegistry as OWNER with contracts/script/RegisterCatalog.s.sol.
# OWNER runs this on their own machine. It never runs in CI (spec 6.8: new apps need registerApp from OWNER).
#
#   scripts/release/register-apps.sh [--apps <id,id>] [--images <images.json>] [--broadcast] [--yes]
#
# Without --broadcast it is a dry run: it prints the plan and lets forge simulate the registrations; nothing
# is sent. With --broadcast it asks for confirmation (skip with --yes), makes sure OWNER's FeeManager fee token
# preference is FEE_TOKEN (D-038), broadcasts with FOUNDRY_PROFILE=deploy (EIP-1559 transactions whose fees
# FeeManager takes in that token, D-038), then checks that every app is registered and prints the
# MAINNET_LEDGER.md rows. Apps that are already registered are skipped, so re-running is safe.
#
# The catalog file comes from catalog/apps/*/manifest.yaml (catalog/tools/release catalog-json): slug = id,
# name, licenseSpdx = upstream.license_spdx, maintainerShareBps, metadataURI = <repo>/tree/main/<app dir>,
# maintainer = payout_address unless it is ${MAINTAINER_DEFAULT_ADDRESS}. --images adds platform images in
# RegisterCatalog's format (addImage); leave it out to register apps only.
#
# Environment (OWNER_PRIVATE_KEY, MAINTAINER_DEFAULT_ADDRESS and TEMPO_RPC_URL are read from SEALED_ENV,
# default ../.env next to the repository, when they are not already set; nothing is printed):
#   OWNER_PRIVATE_KEY, MAINTAINER_DEFAULT_ADDRESS, TEMPO_RPC_URL (default chain.public_rpc_url)
#   EXPECT_CHAIN_ID     default chain.chain_id (4217)
#   CONTRACTS_DIR       default contracts
#   DEPLOYMENTS_FILE    default $CONTRACTS_DIR/deployments/tempo-mainnet.json (must be under $CONTRACTS_DIR/deployments)

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

usage() {
	sed -n '2,6p' "$0" >&2
	exit 2
}

APPS="" IMAGES="" BROADCAST=0 YES=0
while [ $# -gt 0 ]; do
	case "$1" in
	--apps) APPS="${2:-}"; shift 2 ;;
	--images) IMAGES="${2:-}"; shift 2 ;;
	--broadcast) BROADCAST=1; shift ;;
	--yes) YES=1; shift ;;
	-h | --help) usage ;;
	*) log "unknown argument: $1"; usage ;;
	esac
done
need cast
need forge
need jq

# Read only the variables this script needs from the env file, without sourcing it (no code runs, and
# variables already set in the environment win).
load_env_file() {
	local file="$1" line key val
	[ -f "$file" ] || return 0
	while IFS= read -r line || [ -n "$line" ]; do
		line="${line%$'\r'}"
		case "$line" in
		OWNER_PRIVATE_KEY=* | MAINTAINER_DEFAULT_ADDRESS=* | TEMPO_RPC_URL=*) ;;
		*) continue ;;
		esac
		key="${line%%=*}"
		val="${line#*=}"
		val="${val#\"}" && val="${val%\"}"
		val="${val#\'}" && val="${val%\'}"
		if [ -z "${!key:-}" ] && [ -n "$val" ]; then export "$key=$val"; fi
	done <"$file"
}
load_env_file "${SEALED_ENV:-$RELEASE_ROOT/../.env}"

RPC="${TEMPO_RPC_URL:-$(defaults_get publicRpcUrl)}"
EXPECT_CHAIN_ID="${EXPECT_CHAIN_ID:-$(defaults_get chainId)}"
CONTRACTS_DIR="$(cd "${CONTRACTS_DIR:-$RELEASE_ROOT/contracts}" && pwd)"
DEPLOYMENTS_FILE="${DEPLOYMENTS_FILE:-$CONTRACTS_DIR/deployments/tempo-mainnet.json}"
DEPLOYMENTS_FILE="$(cd "$(dirname "$DEPLOYMENTS_FILE")" && pwd)/$(basename "$DEPLOYMENTS_FILE")"
case "$DEPLOYMENTS_FILE" in
"$CONTRACTS_DIR"/deployments/*) DEPLOYMENTS_REL="${DEPLOYMENTS_FILE#"$CONTRACTS_DIR"/}" ;;
*) die "DEPLOYMENTS_FILE must be under $CONTRACTS_DIR/deployments (forge may only read there)" 2 ;;
esac
[ -f "$DEPLOYMENTS_FILE" ] || die "deployments file $DEPLOYMENTS_FILE not found"
FEE_TOKEN="${FEE_TOKEN_ADDRESS:-$(jq -r '.config.feeToken // empty' "$DEPLOYMENTS_FILE")}"
FEE_TOKEN="$(printf '%s' "${FEE_TOKEN:-$(defaults_get feeToken)}" | lower)"

check_chain
refuse_ci_unless_local
REGISTRY="$(deployments_addr AppRegistry)"
require_code "$REGISTRY" AppRegistry
make_keystore OWNER_PRIVATE_KEY
OWNER="$KS_ADDR"
# forge reads both from its environment (vm.envUint, vm.envOr); never from the command line.
export OWNER_PRIVATE_KEY
if [ -n "${MAINTAINER_DEFAULT_ADDRESS:-}" ]; then export MAINTAINER_DEFAULT_ADDRESS; else unset MAINTAINER_DEFAULT_ADDRESS; fi
owner_onchain="$(ccall "$REGISTRY" 'owner()(address)' | lower)"
[ "$owner_onchain" = "$OWNER" ] || die "OWNER_PRIVATE_KEY is $OWNER, but AppRegistry is owned by $owner_onchain" 3
log "ok   chain $CHAIN_ID, AppRegistry $REGISTRY, owner $OWNER"

# The catalog file must be readable by forge: contracts/foundry.toml allows reads under ./catalog only.
CATALOG_REL="catalog/.register-apps.$$.json"
add_cleanup "rm -f '$CONTRACTS_DIR/$CATALOG_REL'"
args=()
[ -n "$APPS" ] && args+=(--apps "$APPS")
[ -n "$IMAGES" ] && args+=(--images "$IMAGES")
release_tool catalog-json ${args[@]+"${args[@]}"} >"$CONTRACTS_DIR/$CATALOG_REL"

pending=()
log ""
log "app                  registered  license          share  maintainer"
while IFS=$'\t' read -r slug license share maint; do
	state="no"
	if [ "$(ccall "$REGISTRY" 'appExists(bytes32)(bool)' "$(cast keccak "$slug")")" = "true" ]; then
		state="yes"
	else
		pending+=("$slug")
		if [ "$maint" = "default" ]; then
			[[ "${MAINTAINER_DEFAULT_ADDRESS:-}" =~ ^0x[0-9a-fA-F]{40}$ ]] ||
				die "$slug uses MAINTAINER_DEFAULT_ADDRESS, which is not set to an address"
			maint="${MAINTAINER_DEFAULT_ADDRESS} (default)"
		fi
	fi
	printf '%-20s %-11s %-16s %-6s %s\n' "$slug" "$state" "$license" "$share" "$maint" >&2
done < <(jq -r '.apps[] | [.slug, .licenseSpdx, (.maintainerShareBps|tostring), (.maintainer // "default")] | @tsv' "$CONTRACTS_DIR/$CATALOG_REL")
images="$(jq '.images | length' "$CONTRACTS_DIR/$CATALOG_REL")"
log ""
if [ "${#pending[@]}" -eq 0 ] && [ "$images" = "0" ]; then
	log "nothing to register"
	exit 0
fi
log "to register: ${pending[*]:-none} (and $images platform image entries, skipped onchain when present)"

forge_env=(env CATALOG_FILE="$CATALOG_REL" DEPLOYMENTS_FILE="$DEPLOYMENTS_REL" FOUNDRY_PROFILE=deploy)
if [ "$BROADCAST" != 1 ]; then
	DRY_RUN=1 ensure_fee_token "$OWNER"
	(cd "$CONTRACTS_DIR" && "${forge_env[@]}" forge script script/RegisterCatalog.s.sol:RegisterCatalog --rpc-url "$RPC") >&2 ||
		die "forge simulation failed"
	log "dry run: nothing sent. Re-run with --broadcast to register."
	exit 0
fi

if [ "$YES" != 1 ]; then
	printf 'Send the registrations on chain %s from %s? Type the chain id to continue: ' "$CHAIN_ID" "$OWNER" >&2
	read -r answer
	[ "$answer" = "$CHAIN_ID" ] || die "not confirmed; nothing sent"
fi
ensure_fee_token "$OWNER"
(cd "$CONTRACTS_DIR" && "${forge_env[@]}" forge script script/RegisterCatalog.s.sol:RegisterCatalog --rpc-url "$RPC" \
	--broadcast --skip-simulation --slow) >&2 || die "forge broadcast failed (re-run to retry: registered apps are skipped)"

for slug in ${pending[@]+"${pending[@]}"}; do
	[ "$(ccall "$REGISTRY" 'appExists(bytes32)(bool)' "$(cast keccak "$slug")")" = "true" ] || die "$slug is still not registered"
	log "ok   $slug registered"
done

# Ledger rows from forge's broadcast record (one per transaction).
run_file="$CONTRACTS_DIR/broadcast/RegisterCatalog.s.sol/$CHAIN_ID/run-latest.json"
if [ -f "$run_file" ]; then
	log ""
	log "MAINNET_LEDGER.md rows:"
	[ -n "$FEE_PREF_TX" ] && log "(setUserToken for OWNER: tx $FEE_PREF_TX)"
	n="$(jq '.receipts | length' "$run_file")"
	for ((i = 0; i < n; i++)); do
		rf="$(mktemp)"
		add_cleanup "rm -f '$rf'"
		jq ".receipts[$i]" "$run_file" >"$rf"
		what="$(jq -r --argjson i "$i" '.transactions[$i] | "\((.function // "call") | split("(")[0]) \(.arguments[1] // "")"' "$run_file")"
		to="$(jq -r '.to // empty' "$rf" | lower)"
		label=PlatformRegistry
		[ "$to" = "$REGISTRY" ] && label=AppRegistry
		ts="$(cast block "$(jq -r .blockNumber "$rf")" -f timestamp --rpc-url "$RPC")"
		release_tool tx-summary --receipt "$rf" --chain-id "$CHAIN_ID" --to "$to" --from-label OWNER \
			--to-label "$label" --purpose "$what" --timestamp "$ts" | jq -r .ledger
	done
fi
