#!/usr/bin/env bash
# Merge transaction hashes, block numbers, gas and fees from a forge broadcast file into a deployments file.
#
#   script/record-deployment.sh deployments/tempo-mainnet.json broadcast/Deploy.s.sol/4217/run-latest.json
#
# Deploy.s.sol writes addresses and constructor arguments during the script run, before anything is sent, so it
# cannot know transaction hashes. Run this right after a successful `--broadcast`. Safe to re-run.
set -euo pipefail

dep="${1:?usage: record-deployment.sh <deployments.json> <run-latest.json>}"
run="${2:?usage: record-deployment.sh <deployments.json> <run-latest.json>}"
[ -f "$dep" ] || { echo "missing $dep" >&2; exit 1; }
[ -f "$run" ] || { echo "missing $run" >&2; exit 1; }

tmp="$(mktemp "${dep}.XXXXXX")"
jq --slurpfile run "$run" '
  def hex2num: if type == "number" then . else
    ltrimstr("0x") | ascii_downcase | explode
    | reduce .[] as $c (0; . * 16 + (if $c >= 97 then $c - 87 else $c - 48 end)) end;
  ($run[0]) as $r
  | ($r.receipts | map({key: .transactionHash, value: .}) | from_entries) as $rc
  | def info($h): ($rc[$h] // {}) as $x
      | { txHash: $h,
          blockNumber: (($x.blockNumber // "0x0") | hex2num),
          gasUsed: (($x.gasUsed // "0x0") | hex2num),
          effectiveGasPrice: (($x.effectiveGasPrice // "0x0") | hex2num),
          status: ($x.status // null) };
    reduce ($r.transactions[] | select(.transactionType == "CREATE" and .contractName != null)) as $tx (.;
      .contracts[$tx.contractName] += (info($tx.hash) | {txHash, blockNumber, gasUsed}))
  | .transactions = [ $r.transactions[] | info(.hash) + {
        type: .transactionType, contract: .contractName, function: .function,
        address: .contractAddress } | .feeUsd = (.gasUsed * .effectiveGasPrice / 1e18) ]
  | .deployBlock = ([.transactions[].blockNumber | select(. > 0)] | min)
  | .totalGasUsed = ([.transactions[].gasUsed] | add)
  | .totalFeeUsd = ([.transactions[].feeUsd] | add)
' "$dep" > "$tmp"
mv "$tmp" "$dep"
echo "recorded $(jq '.transactions | length' "$dep") transactions into $dep (total fee \$$(jq '.totalFeeUsd' "$dep"))"
