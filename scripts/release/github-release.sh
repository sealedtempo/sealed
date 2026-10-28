#!/usr/bin/env bash
# GitHub Release steps of the release job (gh CLI; GH_TOKEN from the workflow).
#
#   github-release.sh publish --tag <tag> --target <commit> --notes <file> --assets <dir>
#       Creates the release as a draft with every file in <dir>, then publishes it. A draft left by an
#       earlier failed run is updated and published. When the tag is already a published release nothing is
#       uploaded and the script prints "exists" (the caller then publishes onchain from that release's own
#       bundle, so a re-run never swaps the bundle of a public release); otherwise it prints "created".
#   github-release.sh notes --tag <tag> --notes <file>
#       Replaces the release notes (used once the publishRelease transaction hash is known).
#   github-release.sh fetch --url <asset url> --sha256 <0x hex> --out <file>
#       Downloads a public asset by its URL, exactly as the key broker, verifierd and the CLI do (D-046),
#       and checks its sha256.
#   github-release.sh state --tag <tag>
#       Prints none, draft or published.
#
# The repository is GH_REPO, else GITHUB_REPOSITORY, else config/defaults.yaml (sealedtempo/sealed).
# Releases are created with --latest=false: one repository carries releases of many apps.

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

CMD="${1:-}"
[ -n "$CMD" ] || die "usage: github-release.sh publish|notes|fetch|state [flags]" 2
shift
TAG="" TARGET="" NOTES="" ASSETS="" URL="" SHA="" OUT=""
while [ $# -gt 0 ]; do
	case "$1" in
	--tag) TAG="${2:-}"; shift 2 ;;
	--target) TARGET="${2:-}"; shift 2 ;;
	--notes) NOTES="${2:-}"; shift 2 ;;
	--assets) ASSETS="${2:-}"; shift 2 ;;
	--url) URL="${2:-}"; shift 2 ;;
	--sha256) SHA="${2:-}"; shift 2 ;;
	--out) OUT="${2:-}"; shift 2 ;;
	*) die "unknown argument: $1" 2 ;;
	esac
done
REPO="${GH_REPO:-${GITHUB_REPOSITORY:-}}"

state() {
	local draft
	if ! draft="$(gh release view "$TAG" --repo "$REPO" --json isDraft --jq .isDraft 2>/dev/null)"; then
		echo none
	elif [ "$draft" = "true" ]; then
		echo draft
	else
		echo published
	fi
}

case "$CMD" in
publish)
	[ -n "$TAG" ] && [ -f "$NOTES" ] && [ -d "$ASSETS" ] && [[ "$TARGET" =~ ^[0-9a-f]{40}$ ]] ||
		die "usage: github-release.sh publish --tag <tag> --target <40 hex commit> --notes <file> --assets <dir>" 2
	need gh
	[ -n "$REPO" ] || REPO="$(defaults_get repo)"
	files=()
	while IFS= read -r f; do files+=("$f"); done < <(find "$ASSETS" -maxdepth 1 -type f | LC_ALL=C sort)
	[ "${#files[@]}" -gt 0 ] || die "no assets in $ASSETS"
	for f in "${files[@]}"; do
		[[ "$(basename "$f")" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "asset name $(basename "$f") would be renamed by GitHub"
	done
	case "$(state)" in
	published)
		log "ok   release $TAG is already published; its assets stay as they are"
		echo exists
		exit 0
		;;
	draft)
		log "update draft release $TAG (left by an earlier run)"
		gh release upload "$TAG" "${files[@]}" --clobber --repo "$REPO" >&2
		gh release edit "$TAG" --notes-file "$NOTES" --repo "$REPO" >&2
		;;
	none)
		log "create draft release $TAG at $TARGET with ${#files[@]} assets"
		gh release create "$TAG" "${files[@]}" --draft --title "$TAG" --notes-file "$NOTES" --target "$TARGET" --latest=false --repo "$REPO" >&2
		;;
	esac
	gh release edit "$TAG" --draft=false --latest=false --repo "$REPO" >&2
	[ "$(state)" = "published" ] || die "release $TAG is not published"
	log "ok   published release $TAG"
	echo created
	;;
notes)
	[ -n "$TAG" ] && [ -f "$NOTES" ] || die "usage: github-release.sh notes --tag <tag> --notes <file>" 2
	need gh
	[ -n "$REPO" ] || REPO="$(defaults_get repo)"
	gh release edit "$TAG" --notes-file "$NOTES" --repo "$REPO" >&2
	log "ok   notes of $TAG updated"
	;;
fetch)
	[[ "$URL" =~ ^https:// ]] && [[ "$SHA" =~ ^0x[0-9a-f]{64}$ ]] && [ -n "$OUT" ] ||
		die "usage: github-release.sh fetch --url <https url> --sha256 <0x hex> --out <file>" 2
	need curl
	ok=0
	for attempt in 1 2 3 4 5; do
		if curl -fsSL --proto '=https' --max-time 300 -o "$OUT" "$URL"; then
			ok=1
			break
		fi
		log "download attempt $attempt failed; retrying"
		sleep $((attempt * 5))
	done
	[ "$ok" = 1 ] || die "cannot download $URL"
	got="0x$( (sha256sum "$OUT" 2>/dev/null || shasum -a 256 "$OUT") | cut -d' ' -f1)"
	[ "$got" = "$SHA" ] || die "$URL has sha256 $got, expected $SHA"
	log "ok   $URL matches $SHA"
	;;
state)
	[ -n "$TAG" ] || die "usage: github-release.sh state --tag <tag>" 2
	need gh
	[ -n "$REPO" ] || REPO="$(defaults_get repo)"
	state
	;;
*) die "unknown command $CMD" 2 ;;
esac
