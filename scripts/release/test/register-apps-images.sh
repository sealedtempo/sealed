#!/usr/bin/env bash
# Test: register-apps.sh --images takes the image measurements files that
# runtime/images/dstack-os/import-and-measure.sh writes ({"images": [...], "sealed": {...}}), not only a bare array,
# and several of them in one run: one per machine shape of the same OS image (D-070, D-078) plus the debug image's.
# Before the first fix catalog/tools/release catalog-json refused the object ("want a JSON array"), found by the
# mainnet fork rehearsal; before the second only one --images file counted. On a local anvil --network tempo node
# with the contracts deployed by script/Deploy.s.sol it checks:
#   1. a measurements file registers its image (addImage) and the app, in the mainnet command shape (--broadcast --yes);
#   2. a re-run sends nothing;
#   3. a file that is neither an array nor an object with an images array is refused with exit 2 before anything is sent;
#   4. --images-only with a c3-standard-8 file, a c3-standard-4 file and the debug image's file adds the three
#      images (the shapes' RTMR0 differ) and registers no app;
#   5. a re-run with the same files, one of them twice, sends nothing;
#   6. two shapes that measured the same values are one image: in one run one addImage is sent, and a later file
#      that repeats a registered set sends nothing;
#   7. conflicting or malformed entries are refused with exit 2 before anything is sent: a shape with two
#      measurement sets, one OS image whose shapes differ in RTMR1, a wrong imageId, a wrong measurementsHash and
#      a measurement that is not 48 bytes.
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

# measurements <out> <name> <os version> <machine type> <rtmr0 label> [rtmr1 label] [isDebug]: a measurements file in
# the exact shape osimage image-json writes, with made-up values (48 bytes from a label). Prints the imageId.
mr() { printf '0x%s%s' "$(cast keccak "test $1" | cut -c3-66)" "$(cast keccak "test $1 b" | cut -c3-34)"; }
measurements() {
	local out="$1" name="$2" osv="$3" mt="$4" r0 r1 mrtd r2 mh id dbg="${7:-false}"
	r0="$(mr "$5")" r1="$(mr "${6:-rtmr1}")" mrtd="$(mr mrtd)" r2="$(mr rtmr2)"
	mh="$(cast keccak "$(cast concat-hex "$mrtd" "$r0" "$r1" "$r2")")"
	id="$(cast keccak "$(cast abi-encode 'f(string,string,bytes32)' "$name" "$osv+$mt" "$mh")")"
	jq -n --arg n "$name" --arg osv "$osv" --arg mt "$mt" --arg m "$mrtd" --arg r0 "$r0" --arg r1 "$r1" --arg r2 "$r2" \
		--arg id "$id" --arg mh "$mh" --argjson dbg "$dbg" --arg os "$(cast keccak "os $name $osv")" \
		'{images: [{name: $n, version: ($osv + "+" + $mt), mrtd: $m, rtmr0: $r0, rtmr1: $r1, rtmr2: $r2, isDebug: $dbg,
		   sourceURI: ("https://example.invalid/" + $n + "-" + $osv + "-gce.tar.gz#sha256=00"), imageId: $id,
		   measurementsHash: $mh, machineTypes: [$mt], boots: 2, osImageHash: $os, gceTarballSha256: "00", trust: "tofu"}],
		  sealed: {schema: "sealed-os-image-catalog/v1", variant: (if $dbg then "debug" else "production" end),
		   sealedOsVersion: $osv}}' >"$out"
	echo "$id"
}

register() { # register [args...]: register-apps.sh against the local node, OWNER = dev key 0
	OWNER_PRIVATE_KEY=$K_OWNER TEMPO_RPC_URL="$NODE" EXPECT_CHAIN_ID=31337 CONTRACTS_DIR="$C" DEPLOYMENTS_FILE="$DEP" \
		MAINTAINER_DEFAULT_ADDRESS=$MAINTAINER FEE_TOKEN_ADDRESS=$ALPHA_USD \
		bash "$ROOT/scripts/release/register-apps.sh" "$@" >"$WORK/run.log" 2>&1
}
images() { cast call "$PR" 'imageCount()(uint256)' --rpc-url "$NODE"; }
approved() { cast call "$PR" 'isApprovedImage(bytes32)(bool)' "$1" --rpc-url "$NODE"; }
status() { cast call "$PR" 'imageStatus(bytes32)(uint8)' "$1" --rpc-url "$NODE"; }

# 1. The measurements file, as import-and-measure.sh writes it.
IMAGE_ID="$(measurements "$WORK/measurements.json" sealed-dstack-os 0.0.0-test c3-standard-8 rtmr0)"
register --apps scraper --images "$WORK/measurements.json" --broadcast --yes || {
	cat "$WORK/run.log"
	fail "register-apps.sh with the measurements file"
}
[ "$(images)" = 1 ] || fail "imageCount"
[ "$(approved "$IMAGE_ID")" = true ] || fail "image $IMAGE_ID is not approved"
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

# refused <message> [args...]: register-apps.sh must exit 2 with <message> and send nothing.
refused() {
	local want="$1" rc=0 n
	shift
	n="$(cast nonce "$OWNER" --rpc-url "$NODE")"
	register "$@" --broadcast --yes || rc=$?
	[ "$rc" = 2 ] && grep -qF "$want" "$WORK/run.log" || {
		cat "$WORK/run.log"
		fail "want exit 2 and '$want' (got $rc)"
	}
	[ "$(cast nonce "$OWNER" --rpc-url "$NODE")" = "$n" ] || fail "a refused run sent a transaction"
}

# 3. Anything else is refused before a transaction.
echo '{"image": {}}' >"$WORK/bad.json"
refused "neither a JSON array" --apps scraper --images "$WORK/bad.json"
ok "3. a malformed images file is refused with exit 2"

# 4. One file per machine shape of one OS image (RTMR0 differs, D-070), plus the debug image, images only.
ID8="$(measurements "$WORK/m8.json" sealed-dstack-os 0.6.1-test c3-standard-8 "r0 c3-standard-8")"
ID4="$(measurements "$WORK/m4.json" sealed-dstack-os 0.6.1-test c3-standard-4 "r0 c3-standard-4")"
IDD="$(measurements "$WORK/mdebug.json" sealed-dstack-os-debug 0.6.1-test c3-standard-8 "r0 debug" "rtmr1 debug" true)"
apps0="$(cast call "$AR" 'appCount()(uint256)' --rpc-url "$NODE")"
register --images-only --images "$WORK/m8.json" --images "$WORK/m4.json" --images "$WORK/mdebug.json" --broadcast --yes || {
	cat "$WORK/run.log"
	fail "three measurements files"
}
[ "$(images)" = 4 ] || fail "imageCount $(images), want 4"
[ "$(approved "$ID8")" = true ] && [ "$(approved "$ID4")" = true ] || fail "the c3-standard-8 and c3-standard-4 images are not approved"
[ "$(status "$IDD")" = 1 ] && [ "$(approved "$IDD")" = false ] || fail "the debug image must be registered and not approved"
[ "$(cast call "$AR" 'appCount()(uint256)' --rpc-url "$NODE")" = "$apps0" ] || fail "--images-only registered an app"
grep -q "ok   image sealed-dstack-os 0.6.1-test+c3-standard-4 approved" "$WORK/run.log" || { cat "$WORK/run.log"; fail "no check line"; }
ok "4. c3-standard-8, c3-standard-4 and debug files in one run: three images, no app"

# 5. The same files again, one of them twice: nothing to send.
n0="$(cast nonce "$OWNER" --rpc-url "$NODE")"
register --images-only --images "$WORK/m4.json" --images "$WORK/m8.json" --images "$WORK/m8.json" --images "$WORK/mdebug.json" \
	--broadcast --yes || {
	cat "$WORK/run.log"
	fail "re-run with the three files"
}
grep -q "nothing to register" "$WORK/run.log" && [ "$(cast nonce "$OWNER" --rpc-url "$NODE")" = "$n0" ] || {
	cat "$WORK/run.log"
	fail "the re-run sent a transaction"
}
ok "5. re-run with the same files (one twice) sends nothing"

# 6. Two shapes with the same values share one image (PlatformRegistry keeps one per measurement set).
S8="$(measurements "$WORK/s8.json" sealed-dstack-os 0.6.2-test c3-standard-8 "r0 same")"
S4="$(measurements "$WORK/s4.json" sealed-dstack-os 0.6.2-test c3-standard-4 "r0 same")"
n0="$(cast nonce "$OWNER" --rpc-url "$NODE")"
register --images-only --images "$WORK/s8.json" --images "$WORK/s4.json" --broadcast --yes || {
	cat "$WORK/run.log"
	fail "two shapes with the same values"
}
[ "$(images)" = 5 ] || fail "imageCount $(images), want 5"
[ "$(cast nonce "$OWNER" --rpc-url "$NODE")" = $((n0 + 1)) ] || fail "want one addImage"
grep -q "measured the same values" "$WORK/run.log" || { cat "$WORK/run.log"; fail "no note on the shared image"; }
[ "$(approved "$S4")" = true ] || fail "c3-standard-4 (sorted first) is the registered entry"
[ "$(status "$S8")" = 0 ] || fail "the second entry must not be registered under its own imageId"
S9="$(measurements "$WORK/s9.json" sealed-dstack-os 0.6.2-test c3-highcpu-8 "r0 same")"
n0="$(cast nonce "$OWNER" --rpc-url "$NODE")"
register --images-only --images "$WORK/s9.json" --broadcast --yes || {
	cat "$WORK/run.log"
	fail "a later file that repeats a registered set"
}
grep -q "nothing to register" "$WORK/run.log" && grep -q "as other" "$WORK/run.log" &&
	[ "$(cast nonce "$OWNER" --rpc-url "$NODE")" = "$n0" ] || {
	cat "$WORK/run.log"
	fail "a repeated measurement set must send nothing"
}
[ -n "$S9" ] || fail "imageId"
ok "6. shapes that measured the same are one image; a repeated set sends nothing"

# 7. Conflicts and malformed entries.
measurements "$WORK/m4-again.json" sealed-dstack-os 0.6.1-test c3-standard-4 "r0 c3-standard-4 second run" >/dev/null
refused "has two measurement sets" --images-only --images "$WORK/m4.json" --images "$WORK/m4-again.json"
measurements "$WORK/m4-r1.json" sealed-dstack-os 0.6.3-test c3-standard-4 "r0 c3-standard-4" "rtmr1 other" >/dev/null
measurements "$WORK/m8-r1.json" sealed-dstack-os 0.6.3-test c3-standard-8 "r0 c3-standard-8" >/dev/null
refused "differ in rtmr1" --images-only --images "$WORK/m8-r1.json" --images "$WORK/m4-r1.json"
jq '.images[0].imageId = "0x" + ("ab" * 32)' "$WORK/m8-r1.json" >"$WORK/bad-id.json"
refused "imageId 0xabab" --images-only --images "$WORK/bad-id.json"
jq '.images[0].measurementsHash = "0x" + ("cd" * 32)' "$WORK/m8-r1.json" >"$WORK/bad-mh.json"
refused "measurementsHash 0xcdcd" --images-only --images "$WORK/bad-mh.json"
jq '.images[0].rtmr0 |= .[0:-2]' "$WORK/m8-r1.json" >"$WORK/short.json"
refused "rtmr0 is not 48 bytes of hex" --images-only --images "$WORK/short.json"
[ "$(images)" = 5 ] || fail "a refused run added an image"
ok "7. two sets for one shape, one image differing in RTMR1, a wrong imageId or measurementsHash, a short RTMR: exit 2"

echo "PASS register-apps.sh --images takes one or several image measurements files"
