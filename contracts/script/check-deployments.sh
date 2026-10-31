#!/usr/bin/env bash
# Checks that a deployments file carries everything spec 4.8 asks for, for each of the five contracts:
#   - address, constructorArgs, txHash, blockNumber and gasUsed, and a successful CREATE with the same hash, block
#     and address in "transactions";
#   - its ABI, equal to abi/<Name>.json (make abi writes those from the source in this tree);
#   - its source verification at the Sourcify-compatible verifier (script/record-verification.sh writes it): the
#     lookup URL names the address, and runtime and creation bytecode both match.
# It also checks that every transaction succeeded and that deployBlock and totalGasUsed agree with them.
# Read only: no RPC, no keys, no network.
#
#   script/check-deployments.sh [deployments file] [abi dir]   # or: make deployments-check
#
# Defaults: deployments/tempo-mainnet.json and the abi directory next to this script.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
dep="${1:-$here/deployments/tempo-mainnet.json}"
abi_dir="${2:-$here/abi}"
CONTRACTS="PlatformRegistry AppRegistry OracleSignatureVerifier DeploymentRegistry FeeSplitter"

[ -f "$dep" ] || { echo "FAIL: $dep not found" >&2; exit 1; }
jq -e 'type == "object"' "$dep" >/dev/null 2>&1 || { echo "FAIL: $dep is not a JSON object" >&2; exit 1; }

# The ABIs to compare with, as one object {Name: abi}.
abis="$(mktemp)"
trap 'rm -f "$abis"' EXIT
echo '{}' >"$abis"
for c in $CONTRACTS; do
	f="$abi_dir/$c.json"
	[ -f "$f" ] || { echo "FAIL: $f not found (make abi)" >&2; exit 1; }
	jq --arg c "$c" --slurpfile a "$f" '. + {($c): $a[0]}' "$abis" >"$abis.new" && mv "$abis.new" "$abis"
done

errors="$(jq -r --slurpfile abis "$abis" --arg names "$CONTRACTS" '
  def addr: type == "string" and test("^0x[0-9a-fA-F]{40}$") and (ascii_downcase != "0x0000000000000000000000000000000000000000");
  def hash: type == "string" and test("^0x[0-9a-fA-F]{64}$");
  def hex: type == "string" and test("^0x([0-9a-fA-F]{2})*$");
  def posint: type == "number" and . > 0 and . == floor;
  def matched: . == "exact_match" or . == "match";
  def lc: if type == "string" then ascii_downcase else . end;
  . as $d
  | ($abis[0]) as $want
  | ($d.transactions // []) as $txs
  | [
      (if ($d.chainId | posint) then empty else "chainId is not a positive integer" end),
      (if ($d.network | type) == "string" and ($d.network | length) > 0 then empty else "network is missing" end),
      (if ($d.deployer | addr) then empty else "deployer is not an address" end),
      ($names | split(" ")[] as $n
        | ($d.contracts[$n] // null) as $c
        | if $c == null then "\($n): missing from contracts" else
            (if ($c.address | addr) then empty else "\($n): address is not a non-zero address" end),
            (if ($c.constructorArgs | hex) then empty else "\($n): constructorArgs is not hex" end),
            (if ($c.txHash | hash) then empty else "\($n): txHash is not a transaction hash" end),
            (if ($c.blockNumber | posint) then empty else "\($n): blockNumber is not a block number" end),
            (if ($c.gasUsed | posint) then empty else "\($n): gasUsed is missing" end),
            ([$txs[] | select(.txHash == $c.txHash)] as $m
              | if ($m | length) != 1 then "\($n): txHash is not one entry of transactions"
                elif $m[0].type != "CREATE" or $m[0].contract != $n then "\($n): its transaction is not the CREATE of \($n)"
                elif ($m[0].address | lc) != ($c.address | lc) then "\($n): its transaction created \($m[0].address), not \($c.address)"
                elif $m[0].blockNumber != $c.blockNumber then "\($n): its transaction is in block \($m[0].blockNumber), not \($c.blockNumber)"
                else empty end),
            (if ($c.abi | type) != "array" or ($c.abi | length) == 0 then "\($n): abi is missing"
              elif $c.abi != $want[$n] then "\($n): abi differs from abi/\($n).json"
              else empty end),
            ($c.verification as $v
              | if ($v | type) != "object" then "\($n): verification is missing (script/record-verification.sh)"
                else
                  (if $v.verifier == "sourcify" then empty else "\($n): verification.verifier is not sourcify" end),
                  (if ($v.url | type) == "string" and ($v.url | startswith("https://"))
                      and ($v.url | ascii_downcase | endswith("/" + ($c.address | ascii_downcase))) then empty
                    else "\($n): verification.url is not an https lookup of \($c.address)" end),
                  (if ($v.runtimeMatch | matched) then empty else "\($n): verification.runtimeMatch is \($v.runtimeMatch)" end),
                  (if ($v.creationMatch | matched) then empty else "\($n): verification.creationMatch is \($v.creationMatch)" end),
                  (if ($v.checkedAt | type) == "string" and ($v.checkedAt | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T")) then empty
                    else "\($n): verification.checkedAt is missing" end)
                end)
          end),
      (if ($txs | length) == 0 then "transactions is empty"
        else
          ($txs[] | select(.status != "0x1") | "transaction \(.txHash) has status \(.status)"),
          (if $d.deployBlock == ([$txs[].blockNumber] | min) then empty else "deployBlock is not the first transaction block" end),
          (if $d.totalGasUsed == ([$txs[].gasUsed] | add) then empty else "totalGasUsed is not the sum of gasUsed" end)
        end)
    ]
  | .[]' "$dep")"

if [ -n "$errors" ]; then
	while IFS= read -r line; do echo "FAIL: $(basename "$dep"): $line" >&2; done <<<"$errors"
	exit 1
fi
echo "ok   $(basename "$dep"): $(echo "$CONTRACTS" | wc -w | tr -d ' ') contracts with address, tx hash, block, gas, ABI and verification (spec 4.8)"
