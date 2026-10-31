#!/usr/bin/env bash
# Tests of the spec 4.8 deployments file and the scripts that write it, without a network:
#   1. deployments/tempo-mainnet.json passes script/check-deployments.sh;
#   2. the file as it was before spec 4.8 was checked (no ABIs, no verification) fails, and so does each broken field;
#   3. script/record-deployment.sh rebuilds the committed file's ABIs and transactions from the committed mainnet
#      broadcast and abi/*.json;
#   4. script/record-verification.sh records a Sourcify v2 lookup (a local fake verifier), and refuses a contract
#      that is not verified, a bytecode that only partly matches, and a verified ABI that differs.
#
#   script/test/deployments.sh   # from the contracts directory, or: make deployments-check
#
# Needs jq, python3 and curl.
set -euo pipefail

cd "$(dirname "$0")/../.."
DEP=deployments/tempo-mainnet.json
RUN=broadcast/Deploy.s.sol/4217/run-latest.json
WORK="$(mktemp -d "${TMPDIR:-/tmp}/deployments-test.XXXXXX")"
PID=""
cleanup() {
	[ -z "$PID" ] || { kill "$PID" && wait "$PID"; } 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
ok() { echo "ok   $*"; }
for t in jq python3 curl; do command -v "$t" >/dev/null || fail "$t is not installed"; done

# expect_fail <file> <message>...: check-deployments.sh must fail on <file> and print every message.
expect_fail() {
	local f="$1" m
	shift
	if script/check-deployments.sh "$f" >"$WORK/out" 2>&1; then
		cat "$WORK/out"
		fail "check-deployments.sh passed $f"
	fi
	for m in "$@"; do grep -qF "$m" "$WORK/out" || { cat "$WORK/out"; fail "no '$m' for $f"; }; done
}
# mutate <jq filter> <message>: the committed file changed by <filter> must fail with <message>.
mutate() {
	jq "$1" "$DEP" >"$WORK/mutated.json"
	expect_fail "$WORK/mutated.json" "$2"
}

# 1.
script/check-deployments.sh "$DEP" >/dev/null || fail "$DEP does not pass check-deployments.sh"
ok "1. $DEP has every spec 4.8 field"

# 2.
jq 'del(.contracts[].abi, .contracts[].verification)' "$DEP" >"$WORK/before.json"
expect_fail "$WORK/before.json" "PlatformRegistry: abi is missing" "FeeSplitter: abi is missing" \
	"AppRegistry: verification is missing"
mutate '.contracts.AppRegistry.abi[0].name = "renamed"' "AppRegistry: abi differs from abi/AppRegistry.json"
mutate '.contracts.FeeSplitter.verification.creationMatch = null' "FeeSplitter: verification.creationMatch is null"
mutate '.contracts.FeeSplitter.verification.runtimeMatch = "partial"' "FeeSplitter: verification.runtimeMatch is partial"
mutate '.contracts.DeploymentRegistry.verification.url |= sub("0x[0-9a-fA-F]{40}$"; "0x0000000000000000000000000000000000000001")' \
	"DeploymentRegistry: verification.url is not an https lookup"
mutate 'del(.contracts.OracleSignatureVerifier.verification.checkedAt)' "OracleSignatureVerifier: verification.checkedAt is missing"
mutate '.contracts.PlatformRegistry.txHash = .transactions[5].txHash' "PlatformRegistry: its transaction is not the CREATE"
mutate '.contracts.AppRegistry.blockNumber = 1' "AppRegistry: its transaction is in block"
mutate '.contracts.AppRegistry.address = "0x0000000000000000000000000000000000000000"' "AppRegistry: address is not a non-zero address"
mutate '.transactions[7].status = "0x0"' "has status 0x0"
mutate 'del(.contracts.FeeSplitter)' "FeeSplitter: missing from contracts"
mutate '.totalGasUsed += 1' "totalGasUsed is not the sum of gasUsed"
ok "2. the pre-4.8 file and each broken field fail"

# 3.
cp "$WORK/before.json" "$WORK/rebuilt.json"
script/record-deployment.sh "$WORK/rebuilt.json" "$RUN" >/dev/null
[ "$(jq -S . "$WORK/rebuilt.json")" = "$(jq -S 'del(.contracts[].verification)' "$DEP")" ] ||
	fail "record-deployment.sh does not rebuild $DEP from $RUN and abi/"
mkdir "$WORK/abi-missing"
cp abi/PlatformRegistry.json "$WORK/abi-missing/"
cp "$WORK/before.json" "$WORK/partial.json"
if ABI_DIR="$WORK/abi-missing" script/record-deployment.sh "$WORK/partial.json" "$RUN" >"$WORK/out" 2>&1; then
	fail "record-deployment.sh recorded a file without every ABI"
fi
grep -q "missing $WORK/abi-missing/AppRegistry.json" "$WORK/out" || { cat "$WORK/out"; fail "no missing-ABI message"; }
cmp -s "$WORK/partial.json" "$WORK/before.json" || fail "a refused record-deployment.sh changed the file"
ok "3. record-deployment.sh rebuilds the ABIs and transactions from $RUN"

# 4. A fake verifier: GET /v2/contract/<chain>/<address> answers $WORK/sourcify/<address, lowercase>.json, else 404.
mkdir "$WORK/sourcify"
cat >"$WORK/sourcify.py" <<'EOF'
import os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
root = sys.argv[1]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        f = os.path.join(root, parts[-1].lower() + ".json") if len(parts) == 4 and parts[:2] == ["v2", "contract"] else ""
        code, body = (200, open(f, "rb").read()) if f and os.path.exists(f) else (404, b'{"customCode":"not_found"}')
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
s = HTTPServer(("127.0.0.1", 0), H)
print(s.server_address[1], flush=True)
s.serve_forever()
EOF
python3 -I "$WORK/sourcify.py" "$WORK/sourcify" >"$WORK/port" &
PID=$!
for _ in $(seq 1 50); do [ -s "$WORK/port" ] && break; sleep 0.1; done
[ -s "$WORK/port" ] || fail "the fake verifier did not start"
TEMPO_VERIFIER_URL="http://127.0.0.1:$(cat "$WORK/port")"
export TEMPO_VERIFIER_URL
answer() { # answer <filter>: every contract's lookup is the committed state changed by <filter>
	for c in $(jq -r '.contracts | keys[]' "$DEP"); do
		jq --arg c "$c" '.contracts[$c] | {match: "exact_match", runtimeMatch: "exact_match", creationMatch: "match",
			chainId: "4217", address, verifiedAt: "2026-10-28T15:50:00Z", abi: (.abi | reverse)}' "$DEP" |
			jq --arg c "$c" "$1" >"$WORK/sourcify/$(jq -r --arg c "$c" '.contracts[$c].address | ascii_downcase' "$DEP").json"
	done
}
record() { # record <file>: record-verification.sh must fail on <file> and leave it unchanged, or (with ok) pass
	cp "$1" "$WORK/before-record.json"
	script/record-verification.sh "$1" >"$WORK/out" 2>&1
}

answer '.'
jq 'del(.contracts[].verification)' "$DEP" >"$WORK/v.json"
record "$WORK/v.json" || { cat "$WORK/out"; fail "record-verification.sh"; }
# The fake verifier is plain http on loopback; check-deployments.sh wants https.
jq --arg b "$TEMPO_VERIFIER_URL" '.contracts[].verification.url |= ("https://contracts.tempo.xyz" + ltrimstr($b))' \
	"$WORK/v.json" >"$WORK/v-https.json"
script/check-deployments.sh "$WORK/v-https.json" >/dev/null ||
	fail "the recorded verification does not pass check-deployments.sh"
want="$TEMPO_VERIFIER_URL/v2/contract/4217/$(jq -r .contracts.FeeSplitter.address "$DEP")"
[ "$(jq -r .contracts.FeeSplitter.verification.url "$WORK/v.json")" = "$want" ] || fail "verification.url"
[ "$(jq -c '.contracts.AppRegistry.verification | [.verifier, .match, .runtimeMatch, .creationMatch, .verifiedAt]' "$WORK/v.json")" = \
	'["sourcify","exact_match","exact_match","match","2026-10-28T15:50:00Z"]' ] || fail "verification fields"
[ "$(jq -S 'del(.contracts[].verification)' "$WORK/v.json")" = "$(jq -S 'del(.contracts[].verification)' "$DEP")" ] ||
	fail "record-verification.sh changed more than verification"
ok "4a. record-verification.sh records each lookup, and the result passes check-deployments.sh"

refused() { # refused <message>: the last record must have failed with <message> and left the file unchanged
	grep -qF "$1" "$WORK/out" || { cat "$WORK/out"; fail "no '$1'"; }
	cmp -s "$WORK/v2.json" "$WORK/before-record.json" || fail "a refused record-verification.sh changed the file"
}
jq 'del(.contracts[].verification)' "$DEP" >"$WORK/v2.json"
rm "$WORK/sourcify/$(jq -r '.contracts.DeploymentRegistry.address | ascii_downcase' "$DEP").json"
if record "$WORK/v2.json"; then fail "an unverified contract was recorded"; fi
refused "DeploymentRegistry: $TEMPO_VERIFIER_URL/v2/contract/4217/$(jq -r .contracts.DeploymentRegistry.address "$DEP") answered HTTP 404"
answer '.creationMatch = null'
if record "$WORK/v2.json"; then fail "a creation mismatch was recorded"; fi
refused "creationMatch is none"
answer '.abi[0].name = "renamed"'
if record "$WORK/v2.json"; then fail "a differing verified ABI was recorded"; fi
refused "the verified ABI at"
ok "4b. an unverified contract, a creation mismatch and a differing ABI are refused, the file unchanged"

echo "PASS deployments file and scripts (spec 4.8)"
