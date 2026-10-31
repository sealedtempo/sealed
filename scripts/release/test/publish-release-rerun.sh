#!/usr/bin/env bash
# Test: publish-release.sh re-runs of an already published release work behind an RPC that caps eth_getLogs.
#
#   scripts/release/test/publish-release-rerun.sh
#
# The mainnet RPC (https://rpc.tempo.xyz) refuses eth_getLogs over more than 100,000 blocks, and
# AppRegistry was deployed more than 100,000 blocks ago, so one query from the deploy block to the head fails there
# (found by the mainnet fork rehearsal). This test puts a JSON-RPC proxy with a CAP-block limit in front of a local
# anvil --network tempo node, publishes one release, mines past the cap, and checks:
#   1. the re-run exits 0 with alreadyPublished and the original transaction (find-block window);
#   2. the same when cast find-block fails or points far from the publication (chunked scan back to the deploy block);
#   3. a chunk wider than the cap fails with a message that names LOG_CHUNK_BLOCKS;
#   4. a LOG_LOOKBACK_BLOCKS that ends after the publication finds nothing and fails.
# Needs anvil, forge, cast, jq, python3, go (or SEALED_RELEASE_BIN) and contracts/dependencies (make -C contracts deps).
# shellcheck source=scripts/release/test/anvil-lib.sh
. "$(dirname "$0")/anvil-lib.sh"
CAP=1000

# 1. anvil, the capped proxy, the contracts and one registered app.
start_anvil
cat >"$WORK/proxy.py" <<'EOF'
# JSON-RPC proxy that refuses eth_getLogs spanning more than CAP blocks, as the Tempo mainnet RPC does (CAP 100000).
import json, sys, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port, upstream, cap = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
def post(body):
    req = urllib.request.Request(upstream, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return r.read()
def head():
    return int(json.loads(post(b'{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'))["result"], 16)
def num(tag):
    if tag in (None, "latest", "pending", "safe", "finalized"):
        return head()
    return 0 if tag == "earliest" else int(tag, 16)
def refused(call):
    if call.get("method") != "eth_getLogs":
        return None
    f = (call.get("params") or [{}])[0]
    if "blockHash" in f or num(f.get("toBlock")) - num(f.get("fromBlock")) <= cap:
        return None
    return {"jsonrpc": "2.0", "id": call.get("id"), "error": {"code": -32602, "message": f"query exceeds max block range {cap}"}}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        msg = json.loads(body)
        calls = msg if isinstance(msg, list) else [msg]
        errs = [refused(c) for c in calls]
        if any(errs):
            out = json.dumps([e or json.loads(post(json.dumps(c).encode())) for c, e in zip(calls, errs)] if isinstance(msg, list) else errs[0]).encode()
        else:
            out = post(body)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
EOF
PP="$(free_port)"
python3 -I "$WORK/proxy.py" "$PP" "$NODE" "$CAP" &
PIDS+=($!)
RPC="http://127.0.0.1:$PP"
for _ in $(seq 1 100); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.1; done
[ "$(cast chain-id --rpc-url "$RPC")" = 31337 ] || fail "the proxy did not start"
ok "anvil :$AP behind a proxy that caps eth_getLogs at $CAP blocks (:$PP)"
deploy_contracts
cast send --rpc-url "$NODE" --private-key $K_OWNER --tempo.fee-token $ALPHA_USD "$AR" \
	'registerApp(bytes32,string,string,string,address,uint16,string)' "$(cast keccak scraper)" scraper Scraper Apache-2.0 \
	$MAINTAINER 2000 https://example.invalid/scraper >/dev/null 2>&1
ok "AppRegistry $AR deployed at block $(jq -r .contracts.AppRegistry.blockNumber "$DEP"), scraper registered"

# 2. Publish once through the proxy.
APP_ID="$(cast keccak scraper)"
BH="$(cast keccak "bundle one")"
jq -n --arg id "$APP_ID" --arg bh "$BH" --arg e "$(cast keccak egress)" --arg s "$(cast keccak sbom)" \
	--arg rid "$(cast keccak "$(cast abi-encode 'f(bytes32,string,bytes32)' "$APP_ID" 0.1.0 "$BH")")" \
	'{appId: $id, slug: "scraper", version: "0.1.0", bundleHash: $bh, egressPolicyHash: $e, sbomHash: $s, releaseId: $rid}' >"$WORK/info.json"
URIS=(--provenance-uri https://github.com/sealedtempo/sealed/releases/download/scraper-v0.1.0/scraper-0.1.0.bundle.tar.intoto.jsonl
	--signature-uri https://github.com/sealedtempo/sealed/releases/download/scraper-v0.1.0/scraper-0.1.0.bundle.tar.sig)
publish() { # publish <out.json> [VAR=value...]: publish-release.sh through the capped proxy
	local out="$1"
	shift
	env "$@" OPS_PRIVATE_KEY=$K_OPS TEMPO_RPC_URL="$RPC" EXPECT_CHAIN_ID=31337 DEPLOYMENTS_FILE="$DEP" \
		FEE_TOKEN_ADDRESS=$ALPHA_USD bash "$ROOT/scripts/release/publish-release.sh" --info "$WORK/info.json" "${URIS[@]}" \
		--out "$out" >"$WORK/run.log" 2>&1
}
publish "$WORK/first.json" || {
	cat "$WORK/run.log"
	fail "first publish"
}
TX="$(jq -r .txHash "$WORK/first.json")"
[ "$(jq -r .alreadyPublished "$WORK/first.json")" = false ] || fail "first publish record"
ok "published scraper 0.1.0 in $TX"

# 3. Mine past the cap: one query from the deploy block to the head is now refused, as on mainnet.
cast rpc --rpc-url "$NODE" anvil_mine "$(printf '0x%x' $((3 * CAP)))" >/dev/null
FROM="$(jq -r .contracts.AppRegistry.blockNumber "$DEP")"
if cast logs --rpc-url "$RPC" --from-block "$FROM" --to-block latest --address "$AR" >/dev/null 2>&1; then
	fail "the proxy must refuse $FROM..latest"
fi
ok "eth_getLogs $FROM..latest ($(($(cast block-number --rpc-url "$RPC") - FROM)) blocks) is refused"

# 4. The checks.
publish "$WORK/rerun.json" LOG_CHUNK_BLOCKS=$((CAP / 2)) || {
	cat "$WORK/run.log"
	fail "re-run (find-block window)"
}
[ "$(jq -r .txHash "$WORK/rerun.json")" = "$TX" ] && [ "$(jq -r .alreadyPublished "$WORK/rerun.json")" = true ] ||
	fail "re-run record: $(cat "$WORK/rerun.json")"
grep -q "is already published as" "$WORK/run.log" || fail "re-run log"
ok "1. re-run: exit 0, alreadyPublished, same transaction"

# cast find-block fails: the chunked scan from the head back to the deploy block must find it.
mkdir -p "$WORK/bin"
printf '#!/usr/bin/env bash\n[ "${1:-}" = find-block ] && { echo "find-block disabled by the test" >&2; exit 1; }\nexec %q "$@"\n' \
	"$(command -v cast)" >"$WORK/bin/cast"
chmod +x "$WORK/bin/cast"
publish "$WORK/scan.json" PATH="$WORK/bin:$PATH" LOG_CHUNK_BLOCKS=$((CAP / 2)) || {
	cat "$WORK/run.log"
	fail "re-run (chunked scan)"
}
[ "$(jq -r .txHash "$WORK/scan.json")" = "$TX" ] || fail "chunked scan record: $(cat "$WORK/scan.json")"
ok "2. re-run without find-block: the chunked scan finds the same transaction"

# find-block answers a block far from the publication: the window misses and the chunked scan still finds it.
mkdir -p "$WORK/bin2"
printf '#!/usr/bin/env bash\n[ "${1:-}" = find-block ] && exec %q block-number --rpc-url %q\nexec %q "$@"\n' \
	"$(command -v cast)" "$NODE" "$(command -v cast)" >"$WORK/bin2/cast"
chmod +x "$WORK/bin2/cast"
publish "$WORK/miss.json" PATH="$WORK/bin2:$PATH" LOG_CHUNK_BLOCKS=$((CAP / 2)) || {
	cat "$WORK/run.log"
	fail "re-run (window miss)"
}
[ "$(jq -r .txHash "$WORK/miss.json")" = "$TX" ] || fail "window miss record: $(cat "$WORK/miss.json")"
ok "2b. find-block window misses: the chunked scan finds the same transaction"

if publish "$WORK/wide.json" PATH="$WORK/bin:$PATH" LOG_CHUNK_BLOCKS=$((5 * CAP)); then fail "a chunk wider than the cap must fail"; fi
grep -q "LOG_CHUNK_BLOCKS" "$WORK/run.log" || {
	cat "$WORK/run.log"
	fail "the error must name LOG_CHUNK_BLOCKS"
}
ok "3. a chunk wider than the RPC cap fails and names LOG_CHUNK_BLOCKS"

if publish "$WORK/short.json" PATH="$WORK/bin:$PATH" LOG_LOOKBACK_BLOCKS=$CAP; then fail "a lookback that ends after the publication must fail"; fi
grep -q "no ReleasePublished event" "$WORK/run.log" || {
	cat "$WORK/run.log"
	fail "lookback error"
}
ok "4. LOG_LOOKBACK_BLOCKS bounds the scan"

echo "PASS publish-release.sh re-runs behind an eth_getLogs cap of $CAP blocks"
