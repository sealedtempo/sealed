#!/usr/bin/env bash
# Rehearses the mainnet catalog registration (catalog-registration-prep run sheet, steps 3 to 6) on a local Tempo
# node: preflight (script/check-catalog.sh), fresh deploy with script/Deploy.s.sol, OWNER's FeeManager fee-token
# preference (D-038), then RegisterCatalog.s.sol in the mainnet command shape: a dry run, then
# FOUNDRY_PROFILE=deploy --broadcast --skip-simulation --slow with MAINTAINER_DEFAULT_ADDRESS unset. Checks every
# getApp against the file, prints the gas of each transaction, and re-runs to show that nothing more is sent.
#
#   script/rehearse-catalog.sh       # from the contracts directory, or: make rehearse-catalog
#
# Uses only anvil's well-known default dev keys. Nothing here touches a public network.
# Environment: CATALOG_FILE (default catalog/catalog.mainnet.json), REHEARSE_PORT (default 8547), REHEARSE_HARDFORK
# (default T13, mainnet's active hardfork), CATALOG_MANIFESTS (manifest dir for the preflight,
# default ../catalog/apps), REHEARSE_KEEP=1 to leave anvil running afterwards.
set -euo pipefail

cd "$(dirname "$0")/.."
CATALOG="${CATALOG_FILE:-catalog/catalog.mainnet.json}"
PORT="${REHEARSE_PORT:-8547}"
HARDFORK="${REHEARSE_HARDFORK:-T13}"
RPC="http://127.0.0.1:${PORT}"
WORK=".e2e/rehearse"
mkdir -p "$WORK" deployments
DEPLOYMENTS_FILE="deployments/anvil-rehearse.json"
RUN="broadcast/RegisterCatalog.s.sol/31337/run-latest.json"

PATH_USD=0x20C0000000000000000000000000000000000000
ALPHA_USD=0x20C0000000000000000000000000000000000001
FEE_MANAGER=0xfeEC000000000000000000000000000000000000
# Mainnet base fee floor (TIP-1067) and protocol cap, attodollars per gas.
FLOOR=600000000
CAP=12000000000

# anvil default dev keys (mnemonic "test test ... junk"); public, local use only.
K_OWNER=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
K_OPS=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
K_ORACLE=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
K_TREASURY=0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba
addr() { cast wallet address --private-key "$1"; }
OWNER=$(addr $K_OWNER); OPS=$(addr $K_OPS); ORACLE=$(addr $K_ORACLE); TREASURY=$(addr $K_TREASURY)

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
first() { awk '{print $1}'; }
lower() { tr '[:upper:]' '[:lower:]'; }
expect_eq() { [ "$1" = "$2" ] || fail "$3: expected '$2', got '$1'"; echo "ok   $3 = $2"; }
call() { cast call --rpc-url "$RPC" "$@"; }
usd() { echo "scale=6; $1 * $2 / 10^18" | bc | sed 's/^\./0./'; }
register() { # register <profile> <log> [forge flags...]: RegisterCatalog.s.sol in the mainnet command shape
  local profile="$1" log="$2"; shift 2
  env -u MAINTAINER_DEFAULT_ADDRESS -u OWNER_ADDRESS OWNER_PRIVATE_KEY=$K_OWNER CATALOG_FILE="$CATALOG" \
    DEPLOYMENTS_FILE=$DEPLOYMENTS_FILE FOUNDRY_PROFILE="$profile" \
    forge script script/RegisterCatalog.s.sol:RegisterCatalog --rpc-url "$RPC" "$@" > "$log" 2>&1 \
    || { cat "$log"; fail "RegisterCatalog.s.sol $*"; }
}

step "preflight (script/check-catalog.sh)"
script/check-catalog.sh "$CATALOG" "${CATALOG_MANIFESTS:-../catalog/apps}"
N=$(jq '.apps | length' "$CATALOG"); NI=$(jq '.images | length' "$CATALOG")

step "start anvil --network tempo --hardfork $HARDFORK on :$PORT"
if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then fail "port $PORT is already in use"; fi
anvil --network tempo --hardfork "$HARDFORK" --port "$PORT" --gas-limit 500000000 > "$WORK/anvil.log" 2>&1 &
ANVIL_PID=$!
cleanup() { if [ "${REHEARSE_KEEP:-0}" != "1" ]; then kill "$ANVIL_PID" 2>/dev/null || true; fi; }
trap cleanup EXIT
for _ in $(seq 1 100); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.1; done
expect_eq "$(cast chain-id --rpc-url "$RPC")" "31337" "chain id"

step "deploy (script/Deploy.s.sol, as script/local-e2e.sh)"
OWNER_PRIVATE_KEY=$K_OWNER OPS_ADDRESS=$OPS ORACLE_ADDRESS=$ORACLE TREASURY_ADDRESS=$TREASURY \
FEE_TOKEN_ADDRESS=$PATH_USD DEPLOYMENTS_NETWORK=local DEPLOYMENTS_FILE=$DEPLOYMENTS_FILE \
  forge script script/Deploy.s.sol:Deploy --rpc-url "$RPC" --broadcast --slow --tempo.fee-token "$ALPHA_USD" \
  > "$WORK/deploy.log" 2>&1 || { cat "$WORK/deploy.log"; fail "deploy script"; }
script/record-deployment.sh "$DEPLOYMENTS_FILE" broadcast/Deploy.s.sol/31337/run-latest.json
APPS=$(jq -r '.contracts.AppRegistry.address' "$DEPLOYMENTS_FILE")
PLATFORM=$(jq -r '.contracts.PlatformRegistry.address' "$DEPLOYMENTS_FILE")
expect_eq "$(call "$APPS" 'owner()(address)' | lower)" "$(echo "$OWNER" | lower)" "AppRegistry owner"
expect_eq "$(call "$APPS" 'appCount()(uint256)' | first)" "0" "appCount before"

step "OWNER fee-token preference (FeeManager.setUserToken, as make fee-token-pref)"
cast send --rpc-url "$RPC" --private-key $K_OWNER --tempo.fee-token "$ALPHA_USD" "$FEE_MANAGER" \
  'setUserToken(address)' "$ALPHA_USD" > /dev/null
expect_eq "$(call "$FEE_MANAGER" 'userTokens(address)(address)' "$OWNER" | lower)" "$(echo "$ALPHA_USD" | lower)" \
  "OWNER fee token"

# The run sheet's dry run uses the deploy profile (Ethereum rules: 20k gas per new slot, not Tempo's 250k), so its
# gas total is far too low; the default profile simulates with the Tempo hardfork in foundry.toml. Both send nothing.
step "dry runs (no --broadcast): deploy profile, then default profile"
NONCE0=$(cast nonce "$OWNER" --rpc-url "$RPC")
sim_gas() { sed -n 's/.*Estimated total gas used for script: *\([0-9]*\).*/\1/p' "$1" | head -1; }
for profile in deploy default; do
  register $profile "$WORK/dry-run-$profile.log"
  expect_eq "$(grep -c 'app registered:' "$WORK/dry-run-$profile.log" || true)" "$N" "apps the $profile dry run would register"
done
expect_eq "$(cast nonce "$OWNER" --rpc-url "$RPC")" "$NONCE0" "dry runs sent nothing"
SIM_DEPLOY=$(sim_gas "$WORK/dry-run-deploy.log"); SIM_DEFAULT=$(sim_gas "$WORK/dry-run-default.log")
echo "dry-run estimated total gas: deploy profile ${SIM_DEPLOY:-n/a} (Ethereum rules), default profile ${SIM_DEFAULT:-n/a}"

step "broadcast (FOUNDRY_PROFILE=deploy --broadcast --skip-simulation --slow)"
P0=$(call $PATH_USD 'balanceOf(address)(uint256)' "$OWNER" | first)
A0=$(call $ALPHA_USD 'balanceOf(address)(uint256)' "$OWNER" | first)
register deploy "$WORK/broadcast.log" --broadcast --skip-simulation --slow
expect_eq "$(grep -c 'app registered:' "$WORK/broadcast.log" || true)" "$N" "apps registered by the script"
expect_eq "$(grep -c 'image added:' "$WORK/broadcast.log" || true)" "$NI" "images added by the script"
expect_eq "$(call "$APPS" 'appCount()(uint256)' | first)" "$N" "appCount"
expect_eq "$(call $PATH_USD 'balanceOf(address)(uint256)' "$OWNER" | first)" "$P0" "OWNER pathUSD unchanged"
A1=$(call $ALPHA_USD 'balanceOf(address)(uint256)' "$OWNER" | first)
[ "$(echo "$A0 > $A1" | bc)" = "1" ] || fail "fees were not paid in the preference token"
echo "ok   fees paid in the preference token: $(echo "$A0 - $A1" | bc) base units"

step "onchain state equals $CATALOG"
APP_T='(string,string,string,string,address,uint16,uint64)'
for i in $(seq 0 $((N - 1))); do
  slug=$(jq -r ".apps[$i].slug" "$CATALOG"); id=$(cast keccak "$slug")
  expect_eq "$(call "$APPS" 'appAt(uint256)(bytes32)' "$i")" "$id" "appAt($i) = keccak256($slug)"
  got=$(cast call --rpc-url "$RPC" --json "$APPS" "getApp(bytes32)($APP_T)" "$id" \
    | jq -c '.[0] | if type == "string" then (. | fromjson? // .) else . end')
  want=$(jq -c ".apps[$i] | [.slug, .name, .licenseSpdx, .metadataURI, (.maintainer | ascii_downcase),
    .maintainerShareBps]" "$CATALOG")
  have=$(jq -c 'if type == "array" then . else [.slug, .name, .licenseSpdx, .metadataURI, .maintainer,
    .maintainerShareBps, .registeredAt] end | [.[0], .[1], .[2], .[3], (.[4] | ascii_downcase), (.[5] | tonumber)]' \
    <<<"$got")
  expect_eq "$have" "$want" "getApp($slug)"
done

step "gas ($RUN)"
jq -r --arg floor $FLOOR --arg cap $CAP '
  def hex2num: if type == "number" then . else
    ltrimstr("0x") | ascii_downcase | explode
    | reduce .[] as $c (0; . * 16 + (if $c >= 97 then $c - 87 else $c - 48 end)) end;
  (.receipts | map({key: .transactionHash, value: .}) | from_entries) as $rc
  | .transactions[]
  | ($rc[.hash]) as $r
  | [(.function // "?" | sub("\\(.*"; "")), (.arguments[1] // .arguments[0] // ""), ($r.type // "?"), .hash,
     ($r.gasUsed | hex2num), ($r.status)]
  | @tsv' "$RUN" > "$WORK/gas.tsv"
printf '%-12s %-18s %-5s %12s %12s\n' function arg type gasLimit gasUsed
TOTAL=0
while IFS=$'\t' read -r fn arg type hash used status; do
  [ "$status" = "0x1" ] || fail "tx failed: $fn $arg"
  limit=$(cast tx --rpc-url "$RPC" "$hash" gas)   # --skip-simulation: the node's estimate, not in run-latest.json
  printf '%-12s %-18s %-5s %12s %12s\n' "$fn" "$arg" "$type" "$limit" "$used"
  TOTAL=$((TOTAL + used))
done < "$WORK/gas.tsv"
expect_eq "$(wc -l < "$WORK/gas.tsv" | tr -d ' ')" "$((N + NI))" "transactions sent"
expect_eq "$(cut -f3 "$WORK/gas.tsv" | sort -u | tr '\n' ' ')" "0x2 " "every transaction is type 2 (D-038)"
echo "total gasUsed $TOTAL = \$$(usd "$TOTAL" $FLOOR) at the mainnet floor, \$$(usd "$TOTAL" $CAP) at the cap"
echo "dry-run totals: default profile ${SIM_DEFAULT:-n/a}, deploy profile ${SIM_DEPLOY:-n/a} (do not use for costs)"

step "re-run (idempotent)"
NONCE1=$(cast nonce "$OWNER" --rpc-url "$RPC")
register deploy "$WORK/rerun.log" --broadcast --skip-simulation --slow
expect_eq "$(grep -c 'app exists, skipping:' "$WORK/rerun.log" || true)" "$N" "apps skipped"
expect_eq "$(cast nonce "$OWNER" --rpc-url "$RPC")" "$NONCE1" "re-run sent nothing"
expect_eq "$(call "$APPS" 'appCount()(uint256)' | first)" "$N" "appCount after re-run"
expect_eq "$(call "$PLATFORM" 'imageCount()(uint256)' | first)" "$NI" "imageCount after re-run"

printf '\nPASS %s registers on anvil --network tempo --hardfork %s: %s apps, %s images, %s gas\n' \
  "$CATALOG" "$HARDFORK" "$N" "$NI" "$TOTAL"
