# shellcheck shell=bash
# Shared setup for the scripts/release/test/*.sh chain tests. Source it; do not run it.
# A local anvil --network tempo node on a free loopback port, the contracts deployed with script/Deploy.s.sol from a
# copy of contracts/ (the tree stays clean), and anvil's public dev keys. Nothing here touches a public network.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/release-test.XXXXXX")"
PIDS=()
_test_cleanup() {
	local p
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" 2>/dev/null || true
		wait "$p" 2>/dev/null || true
	done
	rm -rf "$WORK"
}
trap _test_cleanup EXIT
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
ok() { echo "ok   $*"; }
free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
for _t in anvil forge cast jq python3; do command -v "$_t" >/dev/null || fail "$_t is not installed"; done
[ -d "$ROOT/contracts/dependencies" ] || fail "contracts/dependencies is missing (make -C contracts deps)"
# Nothing from the caller's environment may point the scripts at a real network or key.
unset TEMPO_RPC_URL ETH_RPC_URL OWNER_PRIVATE_KEY OPS_PRIVATE_KEY MAINTAINER_DEFAULT_ADDRESS DEPLOYMENTS_FILE \
	FEE_TOKEN_ADDRESS EXPECT_CHAIN_ID DRY_RUN FOUNDRY_PROFILE LOG_CHUNK_BLOCKS LOG_LOOKBACK_BLOCKS CI GITHUB_ACTIONS
export SEALED_ENV=/dev/null

# anvil dev keys 0 (OWNER) and 1 (OPS), dev addresses 2 (oracle), 4 (maintainer), 5 (treasury).
# shellcheck disable=SC2034 # used by the tests that source this file
K_OWNER=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# shellcheck disable=SC2034
K_OPS=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
ORACLE=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
# shellcheck disable=SC2034
MAINTAINER=0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65
TREASURY=0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc
PATH_USD=0x20c0000000000000000000000000000000000000
ALPHA_USD=0x20c0000000000000000000000000000000000001

# start_anvil [chain id]: sets NODE (and AP, its port). The chain id defaults to anvil's 31337.
start_anvil() {
	AP="$(free_port)"
	anvil --network tempo --hardfork T12 --host 127.0.0.1 --port "$AP" --gas-limit 500000000 ${1:+--chain-id "$1"} \
		>"$WORK/anvil.log" 2>&1 &
	PIDS+=($!)
	NODE="http://127.0.0.1:$AP"
	for _ in $(seq 1 100); do cast chain-id --rpc-url "$NODE" >/dev/null 2>&1 && return 0; sleep 0.1; done
	fail "anvil did not start"
}

# deploy_contracts: Deploy.s.sol from a copy of contracts/ at $C. Sets C, DEP (deployments file), AR and PR.
deploy_contracts() {
	C="$WORK/contracts"
	mkdir -p "$C/deployments"
	cp -R "$ROOT/contracts/src" "$ROOT/contracts/script" "$ROOT/contracts/catalog" "$ROOT/contracts/abi" "$C/"
	cp "$ROOT/contracts/foundry.toml" "$ROOT/contracts/remappings.txt" "$ROOT/contracts/soldeer.lock" "$C/"
	ln -s "$ROOT/contracts/dependencies" "$C/dependencies"
	(cd "$C" && OWNER_PRIVATE_KEY=$K_OWNER OPS_ADDRESS="$(cast wallet address --private-key $K_OPS)" ORACLE_ADDRESS=$ORACLE \
		TREASURY_ADDRESS=$TREASURY FEE_TOKEN_ADDRESS=$PATH_USD DEPLOYMENTS_NETWORK=local DEPLOYMENTS_FILE=deployments/test.json \
		forge script script/Deploy.s.sol:Deploy --rpc-url "$NODE" --broadcast --slow --tempo.fee-token $ALPHA_USD) \
		>"$WORK/deploy.log" 2>&1 || {
		cat "$WORK/deploy.log"
		fail "deploy"
	}
	(cd "$C" && script/record-deployment.sh deployments/test.json \
		"broadcast/Deploy.s.sol/$(cast chain-id --rpc-url "$NODE")/run-latest.json") >/dev/null
	DEP="$C/deployments/test.json"
	# shellcheck disable=SC2034
	AR="$(jq -r .contracts.AppRegistry.address "$DEP")"
	# shellcheck disable=SC2034
	PR="$(jq -r .contracts.PlatformRegistry.address "$DEP")"
}
