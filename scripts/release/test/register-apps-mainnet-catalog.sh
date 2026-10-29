#!/usr/bin/env bash
# Test: on Tempo mainnet (chain 4217) register-apps.sh registers the apps of the reviewed file,
# contracts/catalog/catalog.mainnet.json, not apps generated from the manifests. The mainnet fork rehearsal found that
# the generated list differs from the reviewed one (tree metadataURIs, alphabetical order so appAt(i) changes, no
# maintainer), so the real run could not use the script. On a local anvil --network tempo node with chain id 4217 and
# the contracts deployed by script/Deploy.s.sol (the test's copy of catalog.mainnet.json names the local registries
# in _network) it checks:
#   1. a dry run plans the six apps of the file with their maintainers, and sends nothing;
#   2. --apps that would register an app before an earlier unregistered one of the file, or names no app of it, is
#      refused with exit 2;
#   3. --apps llm-gateway,scraper registers both as appAt(0) and appAt(1), with the file's blob metadataURI and
#      maintainer, although MAINTAINER_DEFAULT_ADDRESS names another address;
#   4. a full run registers the other four in file order, and a re-run sends nothing;
#   5. --catalog files for other registries, that fail script/check-catalog.sh, or that list images, are refused
#      with exit 2 before anything is sent.
#
#   scripts/release/test/register-apps-mainnet-catalog.sh
#
# Needs anvil, forge, cast, jq, python3, go (or SEALED_RELEASE_BIN) and contracts/dependencies (make -C contracts deps).
# shellcheck source=scripts/release/test/anvil-lib.sh
. "$(dirname "$0")/anvil-lib.sh"

start_anvil 4217
deploy_contracts
OWNER="$(cast wallet address --private-key $K_OWNER)"
REVIEWED="$C/catalog/catalog.mainnet.json"
jq --arg ar "$AR" --arg pr "$PR" --arg o "$OWNER" '._network += {AppRegistry: $ar, PlatformRegistry: $pr, owner: $o}' \
	"$ROOT/contracts/catalog/catalog.mainnet.json" >"$REVIEWED"
FILE_MAINTAINER="$(jq -r '.apps[0].maintainer' "$REVIEWED" | tr '[:upper:]' '[:lower:]')"
[ "$FILE_MAINTAINER" != "$(echo "$MAINTAINER" | tr '[:upper:]' '[:lower:]')" ] || fail "the test needs two different maintainers"
ok "contracts deployed on anvil :$AP, chain $(cast chain-id --rpc-url "$NODE") (AppRegistry $AR)"

register() { # register [args...]: register-apps.sh against the local "mainnet", OWNER = dev key 0
	OWNER_PRIVATE_KEY=$K_OWNER TEMPO_RPC_URL="$NODE" EXPECT_CHAIN_ID=4217 CONTRACTS_DIR="$C" DEPLOYMENTS_FILE="$DEP" \
		MAINTAINER_DEFAULT_ADDRESS=$MAINTAINER FEE_TOKEN_ADDRESS=$ALPHA_USD \
		bash "$ROOT/scripts/release/register-apps.sh" "$@" >"$WORK/run.log" 2>&1
}
nonce() { cast nonce "$OWNER" --rpc-url "$NODE"; }
apps() { cast call "$AR" 'appCount()(uint256)' --rpc-url "$NODE"; }
refused() { # refused <message> [args...]: exit 2 with <message>, nothing sent
	local want="$1" rc=0 n
	shift
	n="$(nonce)"
	register "$@" || rc=$?
	[ "$rc" = 2 ] && grep -qF "$want" "$WORK/run.log" || {
		cat "$WORK/run.log"
		fail "want exit 2 and '$want' (got $rc)"
	}
	[ "$(nonce)" = "$n" ] || fail "a refused run sent a transaction"
}
# app_is <index> <slug>: appAt(index) is slug, with the file's metadataURI and maintainer.
app_is() {
	local i="$1" slug="$2" got
	[ "$(cast call "$AR" 'appAt(uint256)(bytes32)' "$i" --rpc-url "$NODE")" = "$(cast keccak "$slug")" ] ||
		fail "appAt($i) is not $slug"
	got="$(cast call "$AR" 'getApp(bytes32)((string,string,string,string,address,uint16,uint64))' "$(cast keccak "$slug")" \
		--rpc-url "$NODE" | tr '[:upper:]' '[:lower:]')"
	case "$got" in
	*"$(jq -r --arg s "$slug" '.apps[] | select(.slug == $s) | .metadataURI' "$REVIEWED" | tr '[:upper:]' '[:lower:]')"*) ;;
	*) fail "$slug: metadataURI is not the file's: $got" ;;
	esac
	case "$got" in
	*"$FILE_MAINTAINER"*) ;;
	*) fail "$slug: maintainer is not the file's: $got" ;;
	esac
}

# 1.
register || {
	cat "$WORK/run.log"
	fail "dry run"
}
grep -qF "apps: from $REVIEWED" "$WORK/run.log" && grep -q "dry run: nothing sent" "$WORK/run.log" || {
	cat "$WORK/run.log"
	fail "the dry run must plan the reviewed file"
}
for slug in llm-gateway scraper crm coding-agent internal-tools inference-relay; do
	grep -qiE "^$slug +no .*$FILE_MAINTAINER" "$WORK/run.log" || { cat "$WORK/run.log"; fail "plan line for $slug"; }
done
grep -q "(default)" "$WORK/run.log" && fail "a reviewed app fell back to MAINTAINER_DEFAULT_ADDRESS"
[ "$(apps)" = 0 ] || fail "a dry run registered an app"
ok "1. dry run plans the six apps of catalog.mainnet.json with their maintainers"

# 2.
refused "crm comes after llm-gateway scraper" --apps crm --broadcast --yes
refused "comes after llm-gateway" --apps scraper,crm --broadcast --yes
refused "no app nosuch" --apps llm-gateway,nosuch --broadcast --yes
ok "2. out-of-order and unknown --apps are refused"

# 3.
register --apps scraper,llm-gateway --broadcast --yes || {
	cat "$WORK/run.log"
	fail "llm-gateway and scraper"
}
[ "$(apps)" = 2 ] || fail "appCount $(apps), want 2"
app_is 0 llm-gateway
app_is 1 scraper
ok "3. llm-gateway and scraper registered as appAt(0) and appAt(1), with the file's metadataURI and maintainer"

# 4.
register --broadcast --yes || {
	cat "$WORK/run.log"
	fail "the other four"
}
[ "$(apps)" = 6 ] || fail "appCount $(apps), want 6"
i=0
for slug in $(jq -r '.apps[].slug' "$REVIEWED"); do
	app_is "$i" "$slug"
	i=$((i + 1))
done
n0="$(nonce)"
register --broadcast --yes && grep -q "nothing to register" "$WORK/run.log" && [ "$(nonce)" = "$n0" ] || {
	cat "$WORK/run.log"
	fail "the re-run must send nothing"
}
ok "4. all six in file order; the re-run sends nothing"

# 5.
refused "names AppRegistry" --catalog "$ROOT/contracts/catalog/catalog.mainnet.json" --broadcast --yes
jq '.apps[0].name = "Gateway"' "$REVIEWED" >"$WORK/renamed.json"
refused "does not pass contracts/script/check-catalog.sh" --catalog "$WORK/renamed.json" --broadcast --yes
jq '.images = [{name: "x"}]' "$REVIEWED" >"$WORK/with-image.json"
refused "lists images" --catalog "$WORK/with-image.json" --broadcast --yes
ok "5. a file for other registries, one that fails check-catalog.sh, and one with images are refused"

echo "PASS register-apps.sh registers catalog.mainnet.json on chain 4217"
