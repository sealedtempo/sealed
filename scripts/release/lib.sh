# shellcheck shell=bash
# Shared helpers for scripts/release. Source it; do not run it.
#
# Secrets: private keys are read from the environment only. make_keystore turns one into a throwaway
# encrypted keystore (catalog/tools/release keystore), so cast only ever sees a keystore path and a password
# file, never the raw key on a command line. Nothing here prints a key, the password or the RPC URL (an RPC
# URL can carry an API key).

set -euo pipefail

RELEASE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export SEALED_REPO_ROOT="$RELEASE_ROOT"
# Tempo FeeManager precompile: userTokens(address) and setUserToken(address) (D-038).
FEE_MANAGER=0xfeec000000000000000000000000000000000000
REGISTRAR_ROLE=0xedcc084d3dcd65a1f7f23c65c46722faca6953d28e43150a467cf43e5c309238 # keccak256("REGISTRAR_ROLE")

log() { printf '%s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$1" >&2
	exit "${2:-1}"
}
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed"; }
lower() { tr '[:upper:]' '[:lower:]'; }

_CLEANUP=()
add_cleanup() { _CLEANUP+=("$1"); }
_run_cleanup() {
	local i
	for ((i = ${#_CLEANUP[@]} - 1; i >= 0; i--)); do eval "${_CLEANUP[$i]}" || true; done
}
trap _run_cleanup EXIT

# release_tool <command> [flags]: the catalog release tool. Uses SEALED_RELEASE_BIN when set, else builds
# it once for this process.
release_tool() {
	if [ -z "${SEALED_RELEASE_BIN:-}" ]; then
		need go
		local dir
		dir="$(mktemp -d "${TMPDIR:-/tmp}/sealed-release.XXXXXX")"
		add_cleanup "rm -rf '$dir'"
		(cd "$RELEASE_ROOT" && go build -o "$dir/sealed-release" ./catalog/tools/release) || die "cannot build catalog/tools/release"
		SEALED_RELEASE_BIN="$dir/sealed-release"
	fi
	"$SEALED_RELEASE_BIN" "$@"
}

# defaults_get <key>: a value from config/defaults.yaml (chainId, explorerUrl, publicRpcUrl, feeToken, ...).
defaults_get() { release_tool defaults | jq -r --arg k "$1" '.[$k]'; }

# make_keystore <ENV_VAR>: encrypt the key in $ENV_VAR into a throwaway keystore. Sets KS_FILE, KS_PASS and
# KS_ADDR (lowercase address). The keystore is deleted when the script exits.
make_keystore() {
	local var="$1"
	[ -n "${!var:-}" ] || die "$var is not set"
	KS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sealed-ks.XXXXXX")"
	add_cleanup "rm -rf '$KS_DIR'"
	KS_ADDR="$(release_tool keystore --key-env "$var" --dir "$KS_DIR/ks")" || die "$var is not a usable private key"
	KS_FILE="$KS_DIR/ks/keystore.json"
	KS_PASS="$KS_DIR/ks/password"
}

# ccall <to> <sig> [args...]: read-only eth_call.
ccall() { cast call --rpc-url "$RPC" "$@"; }

# csend <to> <sig> [args...]: send a Tempo transaction from the keystore account, paying fees in
# FEE_TOKEN explicitly (D-035). Prints the receipt JSON.
csend() {
	cast send --rpc-url "$RPC" --keystore "$KS_FILE" --password-file "$KS_PASS" --tempo.fee-token "$FEE_TOKEN" --json "$@"
}

# check_chain: the RPC must be the chain EXPECT_CHAIN_ID names.
check_chain() {
	local id
	id="$(cast chain-id --rpc-url "$RPC" 2>/dev/null)" || die "cannot reach the RPC endpoint"
	[ "$id" = "$EXPECT_CHAIN_ID" ] || die "the RPC endpoint serves chain $id, expected $EXPECT_CHAIN_ID"
	CHAIN_ID="$id"
}

# deployments_addr <Contract>: address from the deployments file (lowercase).
deployments_addr() {
	local a
	a="$(jq -r --arg c "$1" '.contracts[$c].address // empty' "$DEPLOYMENTS_FILE")"
	[[ "$a" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "$DEPLOYMENTS_FILE has no address for $1"
	printf '%s\n' "$a" | lower
}

# require_code <address> <name>: the address must hold a contract.
require_code() {
	local code
	code="$(cast code "$1" --rpc-url "$RPC")"
	[ "$code" != "0x" ] && [ -n "$code" ] || die "$2 at $1 has no code on chain $CHAIN_ID"
}

# ensure_fee_token <address>: make FeeManager.userTokens(address) equal FEE_TOKEN (D-038), sending
# setUserToken from the keystore account when it differs. With DRY_RUN=1 it only reports.
# Sets FEE_PREF_TX to the transaction hash when one was sent.
ensure_fee_token() {
	local addr="$1" cur want out
	want="$(printf '%s' "$FEE_TOKEN" | lower)"
	cur="$(ccall "$FEE_MANAGER" 'userTokens(address)(address)' "$addr" | lower)"
	FEE_PREF_TX=""
	if [ "$cur" = "$want" ]; then
		log "ok   fee token preference of $addr is $want"
		return 0
	fi
	if [ "${DRY_RUN:-0}" = 1 ]; then
		log "plan fee token preference of $addr is $cur; a real run sends setUserToken($want) first"
		return 0
	fi
	[ "$(printf '%s' "$addr" | lower)" = "$KS_ADDR" ] || die "ensure_fee_token: $addr is not the signing account"
	log "send setUserToken($want) for $addr (was $cur)"
	out="$(csend "$FEE_MANAGER" 'setUserToken(address)' "$want")" || die "setUserToken failed"
	[ "$(jq -r .status <<<"$out")" = "0x1" ] || die "setUserToken reverted"
	FEE_PREF_TX="$(jq -r .transactionHash <<<"$out")"
	cur="$(ccall "$FEE_MANAGER" 'userTokens(address)(address)' "$addr" | lower)"
	[ "$cur" = "$want" ] || die "fee token preference is $cur after setUserToken"
	log "ok   fee token preference set (tx $FEE_PREF_TX)"
}

# refuse_ci_unless_local: scripts that only OWNER runs by hand refuse CI, except against a local dev
# chain (31337), which is how their tests run.
refuse_ci_unless_local() {
	if [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${CI:-}" ]; then
		[ "${CHAIN_ID:-}" = "31337" ] || die "$(basename "$0") runs only on the OWNER's machine, never in CI"
	fi
}
