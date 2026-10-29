#!/usr/bin/env bash
# Test: contracts/script/RegisterCatalog.s.sol signs without a private key when OWNER_ADDRESS names the owner and
# forge holds the wallet (--unlocked here; --ledger --sender for a hardware wallet). The mainnet fork rehearsal had
# to patch the script for this. On a local anvil --network tempo node with the contracts deployed by
# script/Deploy.s.sol it checks, in the mainnet command shape (FOUNDRY_PROFILE=deploy --broadcast --skip-simulation
# --slow) with catalog/catalog.mainnet.json:
#   1. OWNER_ADDRESS with --unlocked --sender, and no OWNER_PRIVATE_KEY, registers the six apps in file order;
#   2. a re-run sends nothing;
#   3. a key that is not OWNER_ADDRESS, an address that does not own the registries, and neither, each stop the
#      script before anything is sent.
#
#   scripts/release/test/register-catalog-owner-address.sh
#
# Needs anvil, forge, cast, jq, python3 and contracts/dependencies (make -C contracts deps).
# shellcheck source=scripts/release/test/anvil-lib.sh
. "$(dirname "$0")/anvil-lib.sh"

start_anvil
deploy_contracts
OWNER="$(cast wallet address --private-key $K_OWNER)"
OPS="$(cast wallet address --private-key $K_OPS)"
ok "contracts deployed on anvil :$AP (AppRegistry $AR)"

catalog() { # catalog [env...] -- [forge flags...]: RegisterCatalog.s.sol with catalog.mainnet.json, output in $WORK/run.log
	local envs=()
	while [ $# -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
	shift
	(cd "$C" && env ${envs[@]+"${envs[@]}"} CATALOG_FILE=catalog/catalog.mainnet.json DEPLOYMENTS_FILE=deployments/test.json \
		FOUNDRY_PROFILE=deploy forge script script/RegisterCatalog.s.sol:RegisterCatalog --rpc-url "$NODE" "$@") \
		>"$WORK/run.log" 2>&1
}
nonces() { echo "$(cast nonce "$OWNER" --rpc-url "$NODE") $(cast nonce "$OPS" --rpc-url "$NODE")"; }

# 1.
catalog OWNER_ADDRESS="$OWNER" -- --unlocked --sender "$OWNER" --broadcast --skip-simulation --slow || {
	cat "$WORK/run.log"
	fail "RegisterCatalog.s.sol with OWNER_ADDRESS and --unlocked"
}
[ "$(grep -c 'app registered:' "$WORK/run.log")" = 6 ] || { cat "$WORK/run.log"; fail "six apps registered"; }
[ "$(cast call "$AR" 'appCount()(uint256)' --rpc-url "$NODE")" = 6 ] || fail "appCount"
for i in 0 1 2 3 4 5; do
	slug="$(jq -r ".apps[$i].slug" "$ROOT/contracts/catalog/catalog.mainnet.json")"
	[ "$(cast call "$AR" 'appAt(uint256)(bytes32)' "$i" --rpc-url "$NODE")" = "$(cast keccak "$slug")" ] ||
		fail "appAt($i) is not $slug"
done
ok "1. OWNER_ADDRESS without a key registers the six apps of catalog.mainnet.json in file order"

# 2.
n0="$(nonces)"
catalog OWNER_ADDRESS="$OWNER" -- --unlocked --sender "$OWNER" --broadcast --skip-simulation --slow || {
	cat "$WORK/run.log"
	fail "re-run"
}
[ "$(grep -c 'app exists, skipping:' "$WORK/run.log")" = 6 ] && [ "$(nonces)" = "$n0" ] || fail "the re-run sent a transaction"
ok "2. re-run sends nothing"

# 3.
refused() { # refused <error> <env...> -- <forge flags...>
	local want="$1"
	shift
	if catalog "$@"; then
		cat "$WORK/run.log"
		fail "RegisterCatalog.s.sol ran; want $want"
	fi
	grep -q "$want" "$WORK/run.log" || { cat "$WORK/run.log"; fail "no $want"; }
	[ "$(nonces)" = "$n0" ] || fail "a refused run sent a transaction"
}
refused OwnerMismatch OWNER_PRIVATE_KEY=$K_OPS OWNER_ADDRESS="$OWNER" -- --broadcast --skip-simulation --slow
refused NotOwner OWNER_ADDRESS="$OPS" -- --unlocked --sender "$OPS" --broadcast --skip-simulation --slow
refused NoOwner -- --broadcast --skip-simulation --slow
ok "3. a mismatched key, a non-owner and no owner at all stop before sending"

echo "PASS RegisterCatalog.s.sol signs as OWNER_ADDRESS without a key"
