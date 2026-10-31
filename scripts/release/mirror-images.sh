#!/usr/bin/env bash
# Copy upstream images to the catalog registry with crane, digest for digest (spec 5.3: VMs pull only from
# ghcr.io, and the digest a manifest pins must be the digest that registry serves).
#
#   scripts/release/mirror-images.sh <mirror-matrix.json> [--skip-blocked] [--check-public]
#
# The input is `go run ./catalog/tools/release images --format mirror-matrix [--apps ...]`:
# {"include": [{name, from, to, target, digest}, ...], "blocked": [...]}. For each entry the script skips the
# copy when <target> (<registry>/<name>@<digest>) already exists, otherwise runs `crane copy <from> <to>`
# (the whole index, so the digest stays identical), and then checks that both <to> and <target> resolve to
# exactly <digest>. Entries listed under "blocked" (images.yaml never_mirror, for example Twenty under D-049)
# make the script fail before anything is copied; --skip-blocked (the scheduled mirror of the whole catalog)
# reports them as warnings and mirrors the rest. DRY_RUN=1 prints the plan only.
#
# --check-public (spec 5.3.1, G21): copy nothing; instead prove every mirrored image is publicly pullable,
# by resolving <target> with an ANONYMOUS `crane digest` (an empty DOCKER_CONFIG, so no credentials are
# offered) and checking it equals <digest>. A target that does not resolve anonymously, or resolves to a
# different digest, fails the script with a pointer to the make-the-GHCR-packages-public step (D1). Run it
# last, after the mirror, so a release never ships images the VMs cannot pull. --skip-blocked may be given
# too; blocked entries are never in "include", so they are simply not checked.
#
# Registry credentials come from crane's config (crane auth login ghcr.io ... in the workflow).

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

MATRIX="" SKIP_BLOCKED="" CHECK_PUBLIC=0
while [ $# -gt 0 ]; do
	case "$1" in
	--skip-blocked) SKIP_BLOCKED=--skip-blocked; shift ;;
	--check-public) CHECK_PUBLIC=1; shift ;;
	-*) die "unknown argument: $1" 2 ;;
	*) [ -z "$MATRIX" ] || die "unexpected argument: $1" 2; MATRIX="$1"; shift ;;
	esac
done
[ -n "$MATRIX" ] && [ -f "$MATRIX" ] || die "usage: mirror-images.sh <mirror-matrix.json> [--skip-blocked] [--check-public]" 2
need jq
need crane

# check_public: resolve every include target with an anonymous crane digest (empty DOCKER_CONFIG) and make
# sure it equals the pinned digest, proving the package is public. No copy, no credentials.
if [ "$CHECK_PUBLIC" = 1 ]; then
	anon_dir="$(mktemp -d "${TMPDIR:-/tmp}/sealed-anon.XXXXXX")"
	add_cleanup "rm -rf '$anon_dir'"
	n="$(jq '.include | length' "$MATRIX")"
	[ "$n" -gt 0 ] || die "nothing to check: the matrix has no include entries"
	checked=0
	for ((i = 0; i < n; i++)); do
		entry="$(jq -c ".include[$i]" "$MATRIX")"
		name="$(jq -r .name <<<"$entry")"
		target="$(jq -r .target <<<"$entry")"
		digest="$(jq -r .digest <<<"$entry")"
		[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$name: bad digest $digest"
		[ "$target" = "${target%@*}@$digest" ] || die "$name: target must name $digest"
		if ! got="$(DOCKER_CONFIG="$anon_dir" crane digest "$target" 2>/dev/null)"; then
			die "$name: $target is not publicly pullable (anonymous crane digest failed). Make the GHCR package public: open its package settings and set visibility to public (github-readiness D1), then re-run."
		fi
		[ "$got" = "$digest" ] || die "$name: $target resolves anonymously to $got, not $digest"
		log "ok   public $name: $target"
		checked=$((checked + 1))
	done
	log "public-visibility: $checked of $n images are anonymously pullable"
	exit 0
fi

blocked="$(jq -r '(.blocked // [])[] | "\(.name) (\(.source)): \(.blocked)"' "$MATRIX")"
if [ -n "$blocked" ]; then
	[ -n "$SKIP_BLOCKED" ] || die "refusing to mirror images whose license forbids redistribution:
$blocked"
	while IFS= read -r b; do log "warn not mirrored: $b"; done <<<"$blocked"
fi

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
