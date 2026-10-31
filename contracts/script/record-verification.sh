#!/usr/bin/env bash
# Record each contract's source verification (spec 4.8: verify every contract at https://contracts.tempo.xyz) in a
# deployments file, from the verifier's Sourcify v2 lookup:
#
#   script/record-verification.sh deployments/tempo-mainnet.json   # or: make record-verification
#
# For every contract it reads GET <TEMPO_VERIFIER_URL>/v2/contract/<chainId>/<address>?fields=abi (read only, no
# key) and writes .contracts.<Name>.verification: verifier, url (the lookup without the query), match,
# runtimeMatch, creationMatch, verifiedAt when the verifier gives it, and checkedAt (now, UTC). It fails, and
# leaves the file as it was, unless runtime and creation bytecode both match ("exact_match" or "match") and the
# verified ABI, when the verifier returns one, equals the ABI recorded in the file. Run it after make
# verify-mainnet. Safe to re-run.
# Environment: TEMPO_VERIFIER_URL (default https://contracts.tempo.xyz).
set -euo pipefail

dep="${1:?usage: record-verification.sh <deployments.json>}"
[ -f "$dep" ] || { echo "missing $dep" >&2; exit 1; }
base="${TEMPO_VERIFIER_URL:-https://contracts.tempo.xyz}"
base="${base%/}"
chain="$(jq -r '.chainId' "$dep")"
[[ "$chain" =~ ^[0-9]+$ ]] || { echo "$dep has no chainId" >&2; exit 1; }
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

tmp="$(mktemp "${dep}.XXXXXX")"
body="$(mktemp)"
trap 'rm -f "$tmp" "$body"' EXIT
cp "$dep" "$tmp"
for name in $(jq -r '.contracts | keys[]' "$dep"); do
  addr="$(jq -r --arg n "$name" '.contracts[$n].address' "$dep")"
  [[ "$addr" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "$name: no address in $dep" >&2; exit 1; }
  lookup="$base/v2/contract/$chain/$addr"
  code="$(curl -sS --max-time 30 -o "$body" -w '%{http_code}' "$lookup?fields=abi")" ||
    { echo "$name: cannot reach $lookup" >&2; exit 1; }
  [ "$code" = 200 ] || { echo "$name: $lookup answered HTTP $code (not verified?)" >&2; exit 1; }
  jq -e 'type == "object"' "$body" >/dev/null 2>&1 || { echo "$name: $lookup did not answer JSON" >&2; exit 1; }
  for field in runtimeMatch creationMatch; do
    m="$(jq -r --arg f "$field" '.[$f] // "none"' "$body")"
    case "$m" in
    exact_match | match) ;;
    *) echo "$name: $field is $m at $lookup" >&2; exit 1 ;;
    esac
  done
  if jq -e '.abi | type == "array"' "$body" >/dev/null; then
    # Entry order and internalType (absent from some metadata) do not count.
    jq -e --arg n "$name" --slurpfile v "$body" '
      def norm: walk(if type == "object" then del(.internalType) else . end) | sort;
      (.contracts[$n].abi | norm) == ($v[0].abi | norm)' "$dep" >/dev/null ||
      { echo "$name: the verified ABI at $lookup differs from .contracts.$name.abi in $dep" >&2; exit 1; }
  fi
  jq --arg n "$name" --arg url "$lookup" --arg now "$now" --slurpfile v "$body" '
    .contracts[$n].verification = ({verifier: "sourcify", url: $url, match: $v[0].match,
      runtimeMatch: $v[0].runtimeMatch, creationMatch: $v[0].creationMatch}
      + (if $v[0].verifiedAt then {verifiedAt: $v[0].verifiedAt} else {} end) + {checkedAt: $now})' \
    "$tmp" >"$tmp.new"
  mv "$tmp.new" "$tmp"
  echo "ok   $name $addr: runtime $(jq -r .runtimeMatch "$body"), creation $(jq -r .creationMatch "$body")"
done
mv "$tmp" "$dep"
echo "recorded the verification of $(jq '.contracts | length' "$dep") contracts into $dep"
