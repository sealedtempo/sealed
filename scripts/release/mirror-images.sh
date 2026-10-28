#!/usr/bin/env bash
# Copy upstream images to the catalog registry with crane, digest for digest (spec 5.3: VMs pull only from
# ghcr.io, and the digest a manifest pins must be the digest that registry serves).
#
#   scripts/release/mirror-images.sh <mirror-matrix.json>
#
# The input is `go run ./catalog/tools/release images --format mirror-matrix [--apps ...]`:
# {"include": [{name, from, to, target, digest}, ...], "blocked": [...]}. For each entry the script skips the
# copy when <target> (<registry>/<name>@<digest>) already exists, otherwise runs `crane copy <from> <to>`
# (the whole index, so the digest stays identical), and then checks that both <to> and <target> resolve to
# exactly <digest>. Entries listed under "blocked" (images.yaml never_mirror, for example Twenty under D-049)
# make the script fail before anything is copied. DRY_RUN=1 prints the plan only.
#
# Registry credentials come from crane's config (crane auth login ghcr.io ... in the workflow).

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

MATRIX="${1:-}"
[ -n "$MATRIX" ] && [ -f "$MATRIX" ] || die "usage: mirror-images.sh <mirror-matrix.json>" 2
need jq
blocked="$(jq -r '(.blocked // [])[] | "\(.name) (\(.source)): \(.blocked)"' "$MATRIX")"
[ -z "$blocked" ] || die "refusing to mirror images whose license forbids redistribution:
$blocked"
need crane

n="$(jq '.include | length' "$MATRIX")"
copied=0 present=0
for ((i = 0; i < n; i++)); do
	entry="$(jq -c ".include[$i]" "$MATRIX")"
	name="$(jq -r .name <<<"$entry")"
	from="$(jq -r .from <<<"$entry")"
	to="$(jq -r .to <<<"$entry")"
	target="$(jq -r .target <<<"$entry")"
	digest="$(jq -r .digest <<<"$entry")"
	[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$name: bad digest $digest"
	[ "$from" = "${from%@*}@$digest" ] && [ "$target" = "${target%@*}@$digest" ] || die "$name: from and target must name $digest"
	if [ "${DRY_RUN:-0}" = 1 ]; then
		log "plan $name: $from -> $to"
		continue
	fi
	if have="$(crane digest "$target" 2>/dev/null)" && [ "$have" = "$digest" ]; then
		present=$((present + 1))
		if tagged="$(crane digest "$to" 2>/dev/null)" && [ "$tagged" = "$digest" ]; then
			log "ok   $name: $to already present"
		else
			log "tag  $name: $target as ${to##*:}"
			crane tag "$target" "${to##*:}" || die "$name: crane tag failed"
		fi
	else
		log "copy $name: $from -> $to"
		crane copy "$from" "$to" || die "$name: crane copy failed"
		copied=$((copied + 1))
	fi
	for ref in "$to" "$target"; do
		got="$(crane digest "$ref")" || die "$name: $ref does not resolve after the copy"
		[ "$got" = "$digest" ] || die "$name: $ref resolves to $got, not $digest (the mirror must keep the digest)"
	done
	log "ok   $name: $target"
done
log "mirror: $copied copied, $present already present, $n total"
