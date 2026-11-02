#!/usr/bin/env bash
# Open the pull request that pins digests built by the runtime image workflow (D-028).
#
#   open-pin-pr.sh --scope catalog|runtime --results <dir> [--base main] [--run-url <url>] [--commit <sha>]
#
# Runs catalog/tools/release pin for the scope (catalog: manifest digests; runtime: runtime-images.json and
# extra-images.json, which are config data and need no composer version bump post-D-097/D-098), and when anything changed
# commits it on the branch release/pin-<scope>-<short commit> and opens a PR against --base with gh. An open PR
# from the same branch is updated instead. No change, no PR. Prints the PR URL.
# DRY_RUN=1 pins and prints the PR body, then restores the files; nothing is committed or pushed.
#
# GH_TOKEN must allow contents and pull-requests writes. A PR opened with the workflow's GITHUB_TOKEN does not
# start other workflows, so the workflow passes a token from secrets.PIN_PR_TOKEN when it exists.

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

SCOPE="" RESULTS="" BASE=main RUN_URL="" COMMIT="${GITHUB_SHA:-}"
while [ $# -gt 0 ]; do
	case "$1" in
	--scope) SCOPE="${2:-}"; shift 2 ;;
	--results) RESULTS="${2:-}"; shift 2 ;;
	--base) BASE="${2:-}"; shift 2 ;;
	--run-url) RUN_URL="${2:-}"; shift 2 ;;
	--commit) COMMIT="${2:-}"; shift 2 ;;
	*) die "unknown argument: $1" 2 ;;
	esac
done
[ "$SCOPE" = catalog ] || [ "$SCOPE" = runtime ] || die "--scope must be catalog or runtime" 2
[ -d "$RESULTS" ] || die "--results must be a directory of build results" 2
need git
need jq
cd "$RELEASE_ROOT"
[ -z "$(git status --porcelain)" ] || die "the working tree is not clean"

body="$(mktemp)"
add_cleanup "rm -f '$body'"
changes="$(release_tool pin --scope "$SCOPE" --results "$RESULTS" --summary "$body" --run-url "$RUN_URL" --commit "$COMMIT")"
count="$(jq length <<<"$changes")"
if [ "$count" = 0 ]; then
	log "no $SCOPE digest changed; no PR"
	exit 0
fi
files=()
while IFS= read -r f; do files+=("$f"); done < <(jq -r '[.[].file] | unique[]' <<<"$changes")
log "pinned $count digest(s) in ${files[*]}"

if [ "${DRY_RUN:-0}" = 1 ]; then
	cat "$body"
	git checkout -- "${files[@]}"
	log "dry run: files restored; nothing committed"
	exit 0
fi
need gh
short="${COMMIT:0:12}"
[ -n "$short" ] || short="$(git rev-parse --short=12 HEAD)"
branch="release/pin-$SCOPE-$short"
title="$SCOPE: pin image digests built from $short"
[ "$SCOPE" = runtime ] && title="runtime: pin sidecar image digests built from $short"
git switch -c "$branch" >&2
git add -- "${files[@]}"
git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
	commit -q -m "$title" -m "$(jq -r '.[] | "\(.image): \(.new) (\(.file))"' <<<"$changes")" -m "Workflow run: ${RUN_URL:-local}"
git push --force-with-lease origin "$branch" >&2
if url="$(gh pr view "$branch" --json url,state --jq 'select(.state == "OPEN") | .url' 2>/dev/null)" && [ -n "$url" ]; then
	gh pr edit "$branch" --title "$title" --body-file "$body" >&2
else
	url="$(gh pr create --base "$BASE" --head "$branch" --title "$title" --body-file "$body")"
fi
echo "$url"
