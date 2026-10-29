#!/usr/bin/env bash
# Test: register-apps.sh --images takes the image measurements file that
# runtime/images/dstack-os/import-and-measure.sh writes ({"images": [...], "sealed": {...}}), not only a bare array.
# Before the fix catalog/tools/release catalog-json refused it ("want a JSON array"), found by the mainnet fork
# rehearsal. On a local anvil --network tempo node with the contracts deployed by script/Deploy.s.sol it checks:
#   1. a measurements file registers its image (addImage) and the app, in the mainnet command shape (--broadcast --yes);
#   2. a re-run sends nothing;
#   3. a file that is neither an array nor an object with an images array is refused with exit 2 before anything is sent.
#
#   scripts/release/test/register-apps-images.sh
#
# Needs anvil, forge, cast, jq, python3, go (or SEALED_RELEASE_BIN) and contracts/dependencies (make -C contracts deps).
# shellcheck source=scripts/release/test/anvil-lib.sh
. "$(dirname "$0")/anvil-lib.sh"

start_anvil
deploy_contracts
OWNER="$(cast wallet address --private-key $K_OWNER)"
ok "contracts deployed on anvil :$AP (AppRegistry $AR, PlatformRegistry $PR)"

# An images file in the exact shape osimage image-json writes, with made-up measurements.
mr() { printf '0x%s%s' "$(cast keccak "test $1" | cut -c3-66)" "$(cast keccak "test $1 b" | cut -c3-34)"; }
MRTD="$(mr mrtd)" R0="$(mr rtmr0)" R1="$(mr rtmr1)" R2="$(mr rtmr2)"
NAME=sealed-dstack-os VERSION=0.0.0-test+c3-standard-8
MH="$(cast keccak "$(cast concat-hex "$MRTD" "$R0" "$R1" "$R2")")"
IMAGE_ID="$(cast keccak "$(cast abi-encode 'f(string,string,bytes32)' "$NAME" "$VERSION" "$MH")")"
jq -n --arg n "$NAME" --arg v "$VERSION" --arg m "$MRTD" --arg r0 "$R0" --arg r1 "$R1" --arg r2 "$R2" --arg id "$IMAGE_ID" --arg mh "$MH" \
	'{images: [{name: $n, version: $v, mrtd: $m, rtmr0: $r0, rtmr1: $r1, rtmr2: $r2, isDebug: false,
	   sourceURI: "https://example.invalid/sealed-dstack-os-0.0.0-test-gce.tar.gz#sha256=00", imageId: $id, measurementsHash: $mh,
	   machineTypes: ["c3-standard-8"], boots: 2, trust: "tofu"}],
	  sealed: {schema: "sealed-os-image-catalog/v1", variant: "production", sealedOsVersion: "0.0.0-test"}}' >"$WORK/measurements.json"

register() { # register [args...]: register-apps.sh against the local node, OWNER = dev key 0
	OWNER_PRIVATE_KEY=$K_OWNER TEMPO_RPC_URL="$NODE" EXPECT_CHAIN_ID=31337 CONTRACTS_DIR="$C" DEPLOYMENTS_FILE="$DEP" \
		MAINTAINER_DEFAULT_ADDRESS=$MAINTAINER FEE_TOKEN_ADDRESS=$ALPHA_USD \
		bash "$ROOT/scripts/release/register-apps.sh" "$@" >"$WORK/run.log" 2>&1
}

# 1. The measurements file, as import-and-measure.sh writes it.
register --apps scraper --images "$WORK/measurements.json" --broadcast --yes || {
	cat "$WORK/run.log"
	fail "register-apps.sh with the measurements file"
}
[ "$(cast call "$PR" 'imageCount()(uint256)' --rpc-url "$NODE")" = 1 ] || fail "imageCount"
[ "$(cast call "$PR" 'isApprovedImage(bytes32)(bool)' "$IMAGE_ID" --rpc-url "$NODE")" = true ] || fail "image $IMAGE_ID is not approved"
[ "$(cast call "$AR" 'appExists(bytes32)(bool)' "$(cast keccak scraper)" --rpc-url "$NODE")" = true ] || fail "scraper is not registered"
ok "1. measurements file: image $IMAGE_ID added and scraper registered"

# 2. Re-run: the image and the app are skipped, nothing is sent.
n0="$(cast nonce "$OWNER" --rpc-url "$NODE")"
register --apps scraper --images "$WORK/measurements.json" --broadcast --yes || {
	cat "$WORK/run.log"
	fail "re-run"
}
[ "$(cast nonce "$OWNER" --rpc-url "$NODE")" = "$n0" ] || fail "the re-run sent a transaction"
ok "2. re-run sends nothing"

# 3. Anything else is refused before a transaction.
echo '{"image": {}}' >"$WORK/bad.json"
n0="$(cast nonce "$OWNER" --rpc-url "$NODE")"
rc=0
register --apps scraper --images "$WORK/bad.json" --broadcast --yes || rc=$?
[ "$rc" = 2 ] && grep -q "neither a JSON array" "$WORK/run.log" || {
	cat "$WORK/run.log"
	fail "a bad images file must exit 2 (got $rc)"
}
[ "$(cast nonce "$OWNER" --rpc-url "$NODE")" = "$n0" ] || fail "a refused run sent a transaction"
ok "3. a malformed images file is refused with exit 2"

echo "PASS register-apps.sh --images takes the image measurements file"
