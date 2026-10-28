#!/usr/bin/env bash
# End-to-end run on a local Tempo node (anvil --network tempo): deploy with script/Deploy.s.sol, then drive the
# whole lifecycle with cast: add image, register app, publish release, approve stack as a customer, register a
# deployment with an oracle signature, heartbeat, pay fees (customer and enclave signer), withdraw, close, and the
# contract-review fixes (fixed approval content, unique measurements and bundles, quote reuse, per-deployment usage).
# Every step is checked; the script exits non-zero on the first mismatch.
#
#   script/local-e2e.sh            # from the contracts directory, or: make local-e2e
#
# Uses only anvil's well-known default dev keys. Nothing here touches a public network.
# Environment: E2E_PORT (default 8546), E2E_HARDFORK (default T4: Tempo mainnet gas schedule), E2E_KEEP=1 to
# leave anvil running afterwards.
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${E2E_PORT:-8546}"
HARDFORK="${E2E_HARDFORK:-T4}"
RPC="http://127.0.0.1:${PORT}"
WORK=".e2e"
mkdir -p "$WORK" deployments
DEPLOYMENTS_FILE="deployments/local.json"

# Tempo genesis tokens on the local node. Every dev account holds u64::MAX of each.
PATH_USD=0x20C0000000000000000000000000000000000000
ALPHA_USD=0x20C0000000000000000000000000000000000001
# Gas is paid in AlphaUSD (a Tempo 0x76 transaction with fee_token set), so pathUSD balances move only by the
# amounts the contracts transfer and every pathUSD delta below is exact.
FEE=(--tempo.fee-token "$ALPHA_USD")

# anvil default dev keys (mnemonic "test test ... junk"); public, local use only.
K_OWNER=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
K_OPS=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
K_ORACLE=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
K_CUSTOMER=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
K_MAINTAINER=0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
K_TREASURY=0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba
K_ENCLAVE=0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e

addr() { cast wallet address --private-key "$1"; }
OWNER=$(addr $K_OWNER); OPS=$(addr $K_OPS); ORACLE=$(addr $K_ORACLE); CUSTOMER=$(addr $K_CUSTOMER)
MAINTAINER=$(addr $K_MAINTAINER); TREASURY=$(addr $K_TREASURY); ENCLAVE=$(addr $K_ENCLAVE)

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
first() { awk '{print $1}'; }
expect_eq() { [ "$1" = "$2" ] || fail "$3: expected '$2', got '$1'"; echo "ok   $3 = $2"; }
lower() { tr '[:upper:]' '[:lower:]'; }
call() { cast call --rpc-url "$RPC" "$@"; }
TOTAL_GAS=0
send() { # send <key> <to> <sig> [args...]; records gas
  local key="$1"; shift
  local out status gas
  out=$(cast send --rpc-url "$RPC" --private-key "$key" "${FEE[@]}" --json "$@")
  status=$(jq -r '.status' <<<"$out"); gas=$(cast to-dec "$(jq -r '.gasUsed' <<<"$out")")
  [ "$status" = "0x1" ] || fail "tx reverted: $*"
  TOTAL_GAS=$((TOTAL_GAS + gas))
  printf 'tx   %-24s gas %9d  %s\n' "$2" "$gas" "$(jq -r '.transactionHash' <<<"$out")"
}
send_fails() { # send_fails <key> <to> <sig> [args...]: the call must revert
  local key="$1"; shift
  if cast send --rpc-url "$RPC" --private-key "$key" "${FEE[@]}" --json "$@" >/dev/null 2>&1; then
    fail "expected revert: $*"
  fi
  echo "ok   reverted as expected: $2"
}
bal() { call "$PATH_USD" "balanceOf(address)(uint256)" "$1" | first; }
now() { cast block latest --rpc-url "$RPC" -f timestamp; }

step "start anvil --network tempo --hardfork $HARDFORK on :$PORT"
if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then fail "port $PORT is already in use"; fi
# Block gas limit 500M as on mainnet (anvil's default is 30M). Foundry 1.7.1's T4 rules charge about 2x mainnet
# (T12) gas for CREATE, so DeploymentRegistry needs ~27M here and forge's 1.3x estimate margin exceeds 30M.
anvil --network tempo --hardfork "$HARDFORK" --port "$PORT" --gas-limit 500000000 > "$WORK/anvil.log" 2>&1 &
ANVIL_PID=$!
cleanup() { if [ "${E2E_KEEP:-0}" != "1" ]; then kill "$ANVIL_PID" 2>/dev/null || true; fi; }
trap cleanup EXIT
for _ in $(seq 1 100); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.1; done
expect_eq "$(cast chain-id --rpc-url "$RPC")" "31337" "chain id"
expect_eq "$(call $PATH_USD 'decimals()(uint8)')" "6" "pathUSD decimals"

step "deploy (script/Deploy.s.sol)"
OWNER_PRIVATE_KEY=$K_OWNER OPS_ADDRESS=$OPS ORACLE_ADDRESS=$ORACLE TREASURY_ADDRESS=$TREASURY \
FEE_TOKEN_ADDRESS=$PATH_USD DEPLOYMENTS_NETWORK=local DEPLOYMENTS_FILE=$DEPLOYMENTS_FILE \
  forge script script/Deploy.s.sol:Deploy --rpc-url "$RPC" --broadcast --slow "${FEE[@]}" > "$WORK/deploy.log" 2>&1 \
  || { cat "$WORK/deploy.log"; fail "deploy script"; }
script/record-deployment.sh "$DEPLOYMENTS_FILE" broadcast/Deploy.s.sol/31337/run-latest.json
c() { jq -r ".contracts.$1.address" "$DEPLOYMENTS_FILE"; }
PLATFORM=$(c PlatformRegistry); APPS=$(c AppRegistry); VERIFIER=$(c OracleSignatureVerifier)
REGISTRY=$(c DeploymentRegistry); SPLITTER=$(c FeeSplitter)
for name in PlatformRegistry AppRegistry OracleSignatureVerifier DeploymentRegistry FeeSplitter; do
  a=$(c $name); [ "$(cast code "$a" --rpc-url "$RPC")" != "0x" ] || fail "$name has no code"
  printf 'ok   %-24s %s  tx %s\n' "$name" "$a" "$(jq -r ".contracts.$name.txHash" "$DEPLOYMENTS_FILE")"
done
DEPLOY_GAS=$(jq '.totalGasUsed' "$DEPLOYMENTS_FILE")
expect_eq "$(call $APPS 'owner()(address)' | lower)" "$(echo $OWNER | lower)" "AppRegistry owner"
expect_eq "$(call $APPS 'hasRole(bytes32,address)(bool)' "$(cast keccak REGISTRAR_ROLE)" $OPS)" "true" "ops is registrar"
expect_eq "$(call $VERIFIER 'isSigner(address)(bool)' $ORACLE)" "true" "oracle signer"
expect_eq "$(call $REGISTRY 'verifiers(uint8)(address)' 1 | lower)" "$(echo $VERIFIER | lower)" "verifier method 1"
expect_eq "$(call $REGISTRY 'verifiers(uint8)(address)' 2)" "0x0000000000000000000000000000000000000000" "method 2 unset"
expect_eq "$(call $SPLITTER 'treasury()(address)' | lower)" "$(echo $TREASURY | lower)" "treasury"

step "add image (owner)"
MRTD=0x$(printf '11%.0s' $(seq 1 48)); R0=0x$(printf '22%.0s' $(seq 1 48))
R1=0x$(printf '33%.0s' $(seq 1 48)); R2=0x$(printf '44%.0s' $(seq 1 48))
MH=$(cast keccak "$(cast concat-hex $MRTD $R0 $R1 $R2)")
IMAGE_ID=$(cast keccak "$(cast abi-encode 'f(string,string,bytes32)' sealed-os 1.0.0-e2e $MH)")
send $K_OWNER $PLATFORM "addImage(bytes32,string,string,bytes,bytes,bytes,bytes,bool,string)" \
  $IMAGE_ID sealed-os 1.0.0-e2e $MRTD $R0 $R1 $R2 false "https://example.invalid/sealed-os"
expect_eq "$(call $PLATFORM 'isApprovedImage(bytes32)(bool)' $IMAGE_ID)" "true" "image approved"
STORED_MH=$(call $PLATFORM 'getImage(bytes32)((bytes32,bool,uint8,uint64,string,string,string))' $IMAGE_ID | tr -d '(' | cut -d, -f1)
expect_eq "$STORED_MH" "$MH" "onchain measurementsHash"
expect_eq "$(call $PLATFORM 'imageByMeasurements(bytes32)(bytes32)' $MH)" "$IMAGE_ID" "image by measurements"
# The same measurements cannot be registered again under another id (review fix logic-F5).
send_fails $K_OWNER $PLATFORM "addImage(bytes32,string,string,bytes,bytes,bytes,bytes,bool,string)" \
  $(cast keccak other-image-id) sealed-os 1.0.0-again $MRTD $R0 $R1 $R2 false ""

step "register apps (owner, cast) and the example catalog (script/RegisterCatalog.s.sol)"
APP_ID=$(cast keccak llm-gateway)
send $K_OWNER $APPS "registerApp(bytes32,string,string,string,address,uint16,string)" \
  $APP_ID llm-gateway "LLM Gateway" MIT $MAINTAINER 2000 "https://example.invalid/llm-gateway"
APP2_ID=$(cast keccak crm)
send $K_OWNER $APPS "registerApp(bytes32,string,string,string,address,uint16,string)" \
  $APP2_ID crm "CRM" AGPL-3.0-only $MAINTAINER 5000 "https://example.invalid/crm"
OWNER_PRIVATE_KEY=$K_OWNER CATALOG_FILE=catalog/catalog.example.json DEPLOYMENTS_FILE=$DEPLOYMENTS_FILE \
MAINTAINER_DEFAULT_ADDRESS=$MAINTAINER \
  forge script script/RegisterCatalog.s.sol:RegisterCatalog --rpc-url "$RPC" --broadcast --slow "${FEE[@]}" \
  > "$WORK/catalog.log" 2>&1 || { cat "$WORK/catalog.log"; fail "catalog script"; }
grep -q "app exists, skipping: llm-gateway" "$WORK/catalog.log" || fail "catalog script should skip existing apps"
expect_eq "$(call $APPS 'appCount()(uint256)' | first)" "5" "apps registered"

step "publish releases (ops = REGISTRAR)"
BUNDLE=$(cast keccak bundle-llm-gateway-1.0.0); BUNDLE2=$(cast keccak bundle-crm-1.0.0)
send $K_OPS $APPS "publishRelease(bytes32,string,bytes32,bytes32,bytes32,string,string)" \
  $APP_ID 1.0.0 $BUNDLE $(cast keccak egress) $(cast keccak sbom) "https://example.invalid/prov" "https://example.invalid/sig"
send $K_OPS $APPS "publishRelease(bytes32,string,bytes32,bytes32,bytes32,string,string)" \
  $APP2_ID 1.0.0 $BUNDLE2 $(cast keccak egress2) $(cast keccak sbom2) "" ""
RELEASE_ID=$(cast keccak "$(cast abi-encode 'f(bytes32,string,bytes32)' $APP_ID 1.0.0 $BUNDLE)")
RELEASE2_ID=$(cast keccak "$(cast abi-encode 'f(bytes32,string,bytes32)' $APP2_ID 1.0.0 $BUNDLE2)")
expect_eq "$(call $APPS 'latestRelease(bytes32)(bytes32)' $APP_ID)" "$RELEASE_ID" "releaseId = keccak256(abi.encode(appId, version, bundleHash))"
expect_eq "$(call $APPS 'isApprovableRelease(bytes32)(bool)' $RELEASE2_ID)" "true" "release 2 approvable"
send_fails $K_CUSTOMER $APPS "publishRelease(bytes32,string,bytes32,bytes32,bytes32,string,string)" \
  $APP_ID 9.9.9 $BUNDLE $BUNDLE $BUNDLE "" ""
# A published bundle cannot come back as another version (review fix logic-F5).
send_fails $K_OPS $APPS "publishRelease(bytes32,string,bytes32,bytes32,bytes32,string,string)" \
  $APP_ID 1.0.1 $BUNDLE $(cast keccak egress) $(cast keccak sbom) "" ""
expect_eq "$(call $APPS 'releaseByBundle(bytes32,bytes32)(bytes32)' $APP_ID $BUNDLE)" "$RELEASE_ID" "release by bundle"

step "approve stack (customer)"
STACK=$(cast keccak e2e-app-compose.json)
send $K_CUSTOMER $REGISTRY "approveStack(bytes32,bytes32[],bytes32,uint64)" $STACK "[$RELEASE_ID,$RELEASE2_ID]" $IMAGE_ID 0
expect_eq "$(call $REGISTRY 'isStackApproved(address,bytes32)(bool)' $CUSTOMER $STACK)" "true" "stack approved"
# The release list and image are fixed by the first approval (review fix logic-F2); a re-approval repeats them.
send_fails $K_CUSTOMER $REGISTRY "approveStack(bytes32,bytes32[],bytes32,uint64)" $STACK "[$RELEASE_ID]" $IMAGE_ID 0
send $K_CUSTOMER $REGISTRY "approveStack(bytes32,bytes32[],bytes32,uint64)" $STACK "[$RELEASE_ID,$RELEASE2_ID]" $IMAGE_ID 0

step "register deployment with an oracle signature (submitted by ops)"
SALT=$(cast keccak e2e-salt)
DEPLOYMENT_ID=$(cast keccak "$(cast abi-encode 'f(address,bytes32,bytes32)' $CUSTOMER $STACK $SALT)")
ATTESTED_AT=$(now)
RECORD="($DEPLOYMENT_ID,$CUSTOMER,$STACK,$IMAGE_ID,$(cast keccak quote-1),$(cast keccak eventlog-1),$(cast keccak config-1),$ENCLAVE,$ATTESTED_AT)"
RECORD_T="(bytes32,address,bytes32,bytes32,bytes32,bytes32,bytes32,address,uint64)"
DIGEST=$(call $REGISTRY "recordDigest($RECORD_T)(bytes32)" "$RECORD")
SIG=$(cast wallet sign --no-hash "$DIGEST" --private-key $K_ORACLE)
EVIDENCE=$(cast abi-encode 'f(bytes)' "$SIG")
expect_eq "$(call $VERIFIER 'verify(bytes32,bytes)(bool)' $DIGEST $EVIDENCE)" "true" "oracle evidence verifies"
BAD_SIG=$(cast wallet sign --no-hash "$DIGEST" --private-key $K_CUSTOMER)
send_fails $K_OPS $REGISTRY "registerDeployment($RECORD_T,uint8,bytes)" "$RECORD" 1 "$(cast abi-encode 'f(bytes)' "$BAD_SIG")"
send $K_OPS $REGISTRY "registerDeployment($RECORD_T,uint8,bytes)" "$RECORD" 1 "$EVIDENCE"
expect_eq "$(call $REGISTRY 'appInDeployment(bytes32,bytes32)(bool)' $DEPLOYMENT_ID $APP_ID)" "true" "app in deployment"
PARTIES=$(call $REGISTRY 'deploymentParties(bytes32)(uint8,address,address)' $DEPLOYMENT_ID | tr '\n' ' ')
expect_eq "$(echo $PARTIES | awk '{print $1}')" "1" "deployment Active"

step "heartbeat"
HB_AT=$(( $(now) + 2 ))
QUOTE2=$(cast keccak quote-2)
HB_DIGEST=$(call $REGISTRY 'heartbeatDigest(bytes32,bytes32,uint64)(bytes32)' $DEPLOYMENT_ID $QUOTE2 $HB_AT)
HB_EVIDENCE=$(cast abi-encode 'f(bytes)' "$(cast wallet sign --no-hash "$HB_DIGEST" --private-key $K_ORACLE)")
send $K_OPS $REGISTRY "heartbeat(bytes32,bytes32,uint64,uint8,bytes)" $DEPLOYMENT_ID $QUOTE2 $HB_AT 1 "$HB_EVIDENCE"
send_fails $K_OPS $REGISTRY "heartbeat(bytes32,bytes32,uint64,uint8,bytes)" $DEPLOYMENT_ID $QUOTE2 $HB_AT 1 "$HB_EVIDENCE"
# A later heartbeat must carry a new quote (review fix crypto-SEAL-03).
HB_REUSE_AT=$(( HB_AT + 1 ))
HB_REUSE_DIGEST=$(call $REGISTRY 'heartbeatDigest(bytes32,bytes32,uint64)(bytes32)' $DEPLOYMENT_ID $QUOTE2 $HB_REUSE_AT)
send_fails $K_OPS $REGISTRY "heartbeat(bytes32,bytes32,uint64,uint8,bytes)" $DEPLOYMENT_ID $QUOTE2 $HB_REUSE_AT 1 \
  "$(cast abi-encode 'f(bytes)' "$(cast wallet sign --no-hash "$HB_REUSE_DIGEST" --private-key $K_ORACLE)")"

step "pay fees in pathUSD (customer, then enclave signer)"
# The enclave signer is a fresh key in production; here dev account 6, which already holds pathUSD.
S0=$(bal $SPLITTER); C0=$(bal $CUSTOMER); E0=$(bal $ENCLAVE)
send $K_CUSTOMER $PATH_USD "approve(address,uint256)" $SPLITTER 5000000
send $K_CUSTOMER $SPLITTER "payFees(bytes32,bytes32,address,uint256,bytes32)" $DEPLOYMENT_ID $APP_ID $PATH_USD 2500000 $(cast keccak usage-1)
send $K_ENCLAVE $PATH_USD "approve(address,uint256)" $SPLITTER 1000000
send $K_ENCLAVE $SPLITTER "payFees(bytes32,bytes32,address,uint256,bytes32)" $DEPLOYMENT_ID $APP2_ID $PATH_USD 1000000 $(cast keccak usage-1)
send_fails $K_CUSTOMER $SPLITTER "payFees(bytes32,bytes32,address,uint256,bytes32)" $DEPLOYMENT_ID $APP_ID $PATH_USD 1 $(cast keccak usage-1)
send_fails $K_CUSTOMER $SPLITTER "payFees(bytes32,bytes32,address,uint256,bytes32)" $DEPLOYMENT_ID $APP_ID $PATH_USD 5000001 $(cast keccak usage-9)
send_fails $K_MAINTAINER $SPLITTER "payFees(bytes32,bytes32,address,uint256,bytes32)" $DEPLOYMENT_ID $APP_ID $PATH_USD 1 $(cast keccak usage-8)
expect_eq "$(echo "$(bal $SPLITTER) - $S0" | bc)" "3500000" "FeeSplitter received exactly 3.5 pathUSD"
expect_eq "$(echo "$C0 - $(bal $CUSTOMER)" | bc)" "2500000" "customer paid 2.5 pathUSD"
expect_eq "$(echo "$E0 - $(bal $ENCLAVE)" | bc)" "1000000" "enclave signer paid 1 pathUSD"
expect_eq "$(call $SPLITTER 'usagePaid(bytes32,bytes32,bytes32)(uint256)' $DEPLOYMENT_ID $(cast keccak usage-1) $APP_ID | first)" \
  "2500000" "usage paid amount per (deployment, usageHash, app)"
send_fails $K_OWNER $SPLITTER "setTreasury(address)" $SPLITTER
# llm-gateway 20% of 2.5 = 0.5; crm 50% of 1.0 = 0.5 -> maintainer 1.0, treasury 2.5
expect_eq "$(call $SPLITTER 'credited(address,address)(uint256)' $PATH_USD $MAINTAINER | first)" "1000000" "maintainer credit"
expect_eq "$(call $SPLITTER 'credited(address,address)(uint256)' $PATH_USD $TREASURY | first)" "2500000" "treasury credit"
expect_eq "$(call $SPLITTER 'totalCredited(address)(uint256)' $PATH_USD | first)" "$(bal $SPLITTER)" "totalCredited == balance"

step "withdraw (maintainer, treasury)"
M0=$(bal $MAINTAINER); T0=$(bal $TREASURY)
send $K_MAINTAINER $SPLITTER "withdraw(address)" $PATH_USD
send $K_TREASURY $SPLITTER "withdraw(address)" $PATH_USD
send_fails $K_TREASURY $SPLITTER "withdraw(address)" $PATH_USD
expect_eq "$(echo "$(bal $MAINTAINER) - $M0" | bc)" "1000000" "maintainer received 1 pathUSD"
expect_eq "$(echo "$(bal $TREASURY) - $T0" | bc)" "2500000" "treasury received 2.5 pathUSD"
expect_eq "$(bal $SPLITTER)" "0" "FeeSplitter empty"
expect_eq "$(call $SPLITTER 'totalCredited(address)(uint256)' $PATH_USD | first)" "0" "totalCredited 0"

step "pause blocks registrations but not closing; close (customer)"
send $K_OWNER $REGISTRY "pause()"
HB2_AT=$(( $(now) + 3 ))
QUOTE3=$(cast keccak quote-3)
HB2_DIGEST=$(call $REGISTRY 'heartbeatDigest(bytes32,bytes32,uint64)(bytes32)' $DEPLOYMENT_ID $QUOTE3 $HB2_AT)
send_fails $K_OPS $REGISTRY "heartbeat(bytes32,bytes32,uint64,uint8,bytes)" $DEPLOYMENT_ID $QUOTE3 $HB2_AT 1 \
  "$(cast abi-encode 'f(bytes)' "$(cast wallet sign --no-hash "$HB2_DIGEST" --private-key $K_ORACLE)")"
send_fails $K_ENCLAVE $REGISTRY "closeDeployment(bytes32)" $DEPLOYMENT_ID
send $K_CUSTOMER $REGISTRY "closeDeployment(bytes32)" $DEPLOYMENT_ID
send $K_OWNER $REGISTRY "unpause()"
PARTIES=$(call $REGISTRY 'deploymentParties(bytes32)(uint8,address,address)' $DEPLOYMENT_ID | tr '\n' ' ')
expect_eq "$(echo $PARTIES | awk '{print $1}')" "2" "deployment Closed"
send_fails $K_CUSTOMER $SPLITTER "payFees(bytes32,bytes32,address,uint256,bytes32)" $DEPLOYMENT_ID $APP_ID $PATH_USD 1 $(cast keccak usage-2)

step "incident response: revoke a release"
send $K_OWNER $APPS "revokeRelease(bytes32,string)" $RELEASE2_ID "e2e incident"
expect_eq "$(call $REGISTRY 'isStackApproved(address,bytes32)(bool)' $CUSTOMER $STACK)" "false" "stack no longer approved"
# The customer cannot undo the revocation by re-approving the same stackHash without (or with) the revoked release.
send_fails $K_CUSTOMER $REGISTRY "approveStack(bytes32,bytes32[],bytes32,uint64)" $STACK "[$RELEASE_ID]" $IMAGE_ID 0
send_fails $K_CUSTOMER $REGISTRY "approveStack(bytes32,bytes32[],bytes32,uint64)" $STACK "[$RELEASE_ID,$RELEASE2_ID]" $IMAGE_ID 0
expect_eq "$(call $REGISTRY 'isStackApproved(address,bytes32)(bool)' $CUSTOMER $STACK)" "false" "revocation holds"

GAS_PRICE=$(cast gas-price --rpc-url "$RPC")
printf '\nPASS local e2e on anvil --network tempo --hardfork %s\n' "$HARDFORK"
printf 'deploy gas %s, flow gas %s (local base fee %s attodollars/gas)\n' "$DEPLOY_GAS" "$TOTAL_GAS" "$GAS_PRICE"
printf 'addresses in %s\n' "$DEPLOYMENTS_FILE"
