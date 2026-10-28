#!/usr/bin/env bash
# Preflight for a RegisterCatalog.s.sol input before it is registered on mainnet. slug, name and licenseSpdx are
# permanent onchain (AppRegistry has no setter for them), so this refuses the file unless every app entry:
#   - has slug, name, licenseSpdx, maintainer (non-zero), maintainerShareBps (at most 5000), metadataURI and appId;
#   - has appId = keccak256(slug), a unique slug, no "_pending" key and no "PENDING" placeholder in any value;
#   - has metadataURI ending in /catalog/apps/<slug>/manifest.yaml;
#   - matches its manifest: id = slug, name = name, upstream.license_spdx = licenseSpdx,
#     maintainer_share_bps = maintainerShareBps, maintainer.payout_address = maintainer or
#     ${MAINTAINER_DEFAULT_ADDRESS}; and every <manifest dir>/*/manifest.yaml has an entry.
# Read only: no RPC, no keys.
#
#   script/check-catalog.sh [catalog file] [manifest dir]   # or: make catalog-check
#
# Defaults: catalog/catalog.mainnet.json and ../catalog/apps (the public repo's catalog). Without the manifest dir
# the manifest comparison is skipped with a warning, unless CATALOG_STRICT=1.
set -euo pipefail

cd "$(dirname "$0")/.."
CATALOG="${1:-catalog/catalog.mainnet.json}"
MANIFESTS="${2:-../catalog/apps}"
ERRORS=0
err() { echo "FAIL: $*" >&2; ERRORS=$((ERRORS + 1)); }
lower() { tr '[:upper:]' '[:lower:]'; }

[ -f "$CATALOG" ] || { echo "FAIL: $CATALOG not found" >&2; exit 1; }
jq -e '.apps | type == "array" and length > 0' "$CATALOG" >/dev/null || { echo "FAIL: $CATALOG has no apps" >&2; exit 1; }

# Placeholders anywhere in the app entries (keys starting with "_" included, except they may say "pending" in text).
if jq -e '[.apps[] | to_entries[] | select(.key | startswith("_") | not) | .value | tostring | test("PENDING"; "i")] | any' \
  "$CATALOG" >/dev/null; then
  err "an app value contains a PENDING placeholder"
fi
if jq -e '[.apps[] | has("_pending")] | any' "$CATALOG" >/dev/null; then err "an app entry has a _pending key"; fi
dups=$(jq -r '[.apps[].slug] | group_by(.) | map(select(length > 1) | .[0]) | join(" ")' "$CATALOG")
[ -z "$dups" ] || err "duplicate slugs: $dups"

n=$(jq '.apps | length' "$CATALOG")
for i in $(seq 0 $((n - 1))); do
  get() { jq -r ".apps[$i].$1 // empty" "$CATALOG"; }
  slug=$(get slug); name=$(get name); lic=$(get licenseSpdx); maint=$(get maintainer)
  share=$(get maintainerShareBps); uri=$(get metadataURI); appid=$(get appId)
  for kv in "slug=$slug" "name=$name" "licenseSpdx=$lic" "maintainer=$maint" "maintainerShareBps=$share" \
    "metadataURI=$uri" "appId=$appid"; do
    [ -n "${kv#*=}" ] || err "apps[$i] ($slug): missing ${kv%%=*}"
  done
  [ -n "$slug" ] || continue
  [ "$(echo "$appid" | lower)" = "$(cast keccak "$slug")" ] || err "$slug: appId $appid is not keccak256(slug)"
  [[ "$maint" =~ ^0x[0-9a-fA-F]{40}$ ]] && [ "$(echo "$maint" | lower)" != "0x0000000000000000000000000000000000000000" ] \
    || err "$slug: maintainer '$maint' is not a non-zero address"
  [[ "$share" =~ ^[0-9]+$ ]] && [ "$share" -le 5000 ] || err "$slug: maintainerShareBps '$share' is not 0..5000"
  [[ "$uri" == */catalog/apps/"$slug"/manifest.yaml ]] || err "$slug: metadataURI does not end in /catalog/apps/$slug/manifest.yaml"
done

if [ -d "$MANIFESTS" ]; then
  # Top-level scalar, or a key one level under a top-level block. Strips quotes and trailing comments.
  yget() { # yget <file> <key> [parent]
    awk -v key="$2" -v parent="${3:-}" -v q="'" '
      function val(s) { sub(/^[^:]*:[ \t]*/, "", s); sub(/[ \t]+#.*$/, "", s); gsub("^[\"" q "]|[\"" q "]$", "", s); return s }
      parent == "" && $0 ~ "^" key ":" { print val($0); exit }
      parent != "" && $0 ~ "^" parent ":" { inside = 1; next }
      inside && /^[^ \t#]/ { inside = 0 }
      inside && $0 ~ "^[ \t]+" key ":" { print val($0); exit }
    ' "$1"
  }
  for m in "$MANIFESTS"/*/manifest.yaml; do
    [ -f "$m" ] || continue
    id=$(yget "$m" id)
    jq -e --arg s "$id" '[.apps[].slug] | index($s) != null' "$CATALOG" >/dev/null || err "$m: app '$id' has no catalog entry"
  done
  for i in $(seq 0 $((n - 1))); do
    slug=$(jq -r ".apps[$i].slug" "$CATALOG"); m="$MANIFESTS/$slug/manifest.yaml"
    [ -f "$m" ] || { err "$slug: no manifest at $m"; continue; }
    want() { [ "$2" = "$3" ] || err "$slug: $1 is '$3' in the catalog but '$2' in $m"; }
    want id "$(yget "$m" id)" "$slug"
    want name "$(yget "$m" name)" "$(jq -r ".apps[$i].name" "$CATALOG")"
    want licenseSpdx "$(yget "$m" license_spdx upstream)" "$(jq -r ".apps[$i].licenseSpdx" "$CATALOG")"
    want maintainerShareBps "$(yget "$m" maintainer_share_bps)" "$(jq -r ".apps[$i].maintainerShareBps" "$CATALOG")"
    payout=$(yget "$m" payout_address maintainer)
    if [ "$payout" != '${MAINTAINER_DEFAULT_ADDRESS}' ]; then
      want maintainer "$(echo "$payout" | lower)" "$(jq -r ".apps[$i].maintainer" "$CATALOG" | lower)"
    fi
  done
  echo "manifests: compared with $MANIFESTS"
elif [ "${CATALOG_STRICT:-0}" = "1" ]; then
  err "manifest dir $MANIFESTS not found (CATALOG_STRICT=1)"
else
  echo "WARN: manifest dir $MANIFESTS not found; manifest comparison skipped (CATALOG_STRICT=1 makes this fail)"
fi

[ "$ERRORS" -eq 0 ] || { echo "catalog check FAILED with $ERRORS error(s): $CATALOG" >&2; exit 1; }
echo "PASS catalog check: $CATALOG ($n apps, $(jq '.images | length' "$CATALOG") images)"
