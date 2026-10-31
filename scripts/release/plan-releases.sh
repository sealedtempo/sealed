#!/usr/bin/env bash
# Decide which apps the release job releases, or check a pull request's version bumps.
#
#   plan-releases.sh release (--changed <files.txt> | --apps <id,id|all>) [--skip-unready] --out <matrix.json>
#   plan-releases.sh pr-check --changed <files.txt>
#
# release: plans the apps with a changed bundle input (or the given apps) with catalog/tools/release plan
# --strict (every image built and pinned, a releasable version), then reads, without sending anything:
#   - AppRegistry.appExists: an unregistered app fails the plan (OWNER registers apps with
#     contracts/script/RegisterCatalog.s.sol and contracts/catalog/catalog.mainnet.json);
#   - AppRegistry.releaseByVersion: an app whose version is already onchain is complete and dropped, unless its
#     GitHub Release is missing, which fails (a public release must back every onchain bundleHash);
#   - the GitHub Release state of the tag (none, draft, published), passed on to the publish job. A draft or
#     release that github-actions[bot] did not create fails the plan. A release that is published on GitHub
#     but absent onchain is planned as "published-not-onchain" with a warning: the publish job uses it only
#     if its bundle is the one that run built, or is signed by release.yml on main (supply-1).
# --skip-unready (the push trigger, which plans from the onchain state with --apps all, supply-6): an app
# that cannot be released yet (unbuilt images, a version problem, not registered) is skipped with a notice
# instead of failing the plan. Explicit runs keep failing on it.
# Writes {"include": [...planned releases with githubRelease...]} to --out, plus "count".
#
# pr-check: for apps whose bundle inputs a pull request changes, fails when the tag of their version already
# has a GitHub Release, because the merged change could never be released under that version: bump
# release_version. It also reports version problems as warnings.
#
# Environment: TEMPO_RPC_URL (default chain.public_rpc_url), EXPECT_CHAIN_ID, DEPLOYMENTS_FILE (release mode).

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

MODE="${1:-}"
[ "$MODE" = release ] || [ "$MODE" = pr-check ] || die "usage: plan-releases.sh release|pr-check [flags]" 2
shift
CHANGED="" APPS="" OUT="" SKIP_UNREADY=0
while [ $# -gt 0 ]; do
	case "$1" in
	--changed) CHANGED="${2:-}"; shift 2 ;;
	--apps) APPS="${2:-}"; shift 2 ;;
	--out) OUT="${2:-}"; shift 2 ;;
	--skip-unready) SKIP_UNREADY=1; shift ;;
	*) die "unknown argument: $1" 2 ;;
	esac
done
need jq
need gh
GH="$(dirname "$0")/github-release.sh"
sel=()
if [ -n "$APPS" ]; then sel=(--apps "$APPS"); elif [ -n "$CHANGED" ]; then sel=(--changed "$CHANGED"); else die "pass --changed or --apps" 2; fi
plan="$(mktemp)"
add_cleanup "rm -f '$plan'"

if [ "$MODE" = pr-check ]; then
	release_tool plan "${sel[@]}" >"$plan"
	bad=0
	# No empty fields: read collapses consecutive tabs (an app with a version problem has no tag).
	while IFS=$'\t' read -r app version tag; do
		[ "$tag" != "-" ] || continue
		if [ "$(bash "$GH" state --tag "$tag")" != none ]; then
			printf '::error file=catalog/apps/%s/manifest.yaml,title=release-version::%s %s is already released (%s); bump release_version so the change can be released\n' "$app" "$app" "$version" "$tag"
			bad=1
		else
			log "ok   $app: $tag is not released yet"
		fi
	done < <(jq -r '.[] | [.app, .version, (if .tag == "" then "-" else .tag end)] | @tsv' "$plan")
	exit "$bad"
fi

[ -n "$OUT" ] || die "--out is required" 2
need cast
if [ "$SKIP_UNREADY" = 1 ]; then
	release_tool plan "${sel[@]}" >"$plan" || die "the release plan has problems (see above)"
else
	release_tool plan --strict "${sel[@]}" >"$plan" || die "the release plan has problems (see above)"
fi
RPC="${TEMPO_RPC_URL:-$(defaults_get publicRpcUrl)}"
EXPECT_CHAIN_ID="${EXPECT_CHAIN_ID:-$(defaults_get chainId)}"
DEPLOYMENTS_FILE="${DEPLOYMENTS_FILE:-$RELEASE_ROOT/contracts/deployments/tempo-mainnet.json}"
check_chain
REGISTRY="$(deployments_addr AppRegistry)"
require_code "$REGISTRY" AppRegistry
zero="0x$(printf '0%.0s' {1..64})"

entries=()
fail=0
n="$(jq length "$plan")"
for ((i = 0; i < n; i++)); do
	p="$(jq -c ".[$i]" "$plan")"
	app="$(jq -r .app <<<"$p")" version="$(jq -r .version <<<"$p")" tag="$(jq -r .tag <<<"$p")" appid="$(jq -r .appId <<<"$p")"
	if [ "$SKIP_UNREADY" = 1 ] && [ -n "$(jq -r '.problem // empty' <<<"$p")" ]; then
		printf '::notice file=catalog/apps/%s/manifest.yaml,title=not-ready::%s %s is skipped: %s\n' "$app" "$app" "$version" "$(jq -r .problem <<<"$p")"
		continue
	fi
	if [ "$(ccall "$REGISTRY" 'appExists(bytes32)(bool)' "$appid")" != "true" ]; then
		if [ "$SKIP_UNREADY" = 1 ]; then
			printf '::notice file=catalog/apps/%s/manifest.yaml,title=not-registered::%s is skipped: it is not registered in AppRegistry yet\n' "$app" "$app"
			continue
		fi
		printf '::error file=catalog/apps/%s/manifest.yaml,title=not-registered::%s is not registered in AppRegistry; OWNER registers it with contracts/script/RegisterCatalog.s.sol (contracts/catalog/catalog.mainnet.json)\n' "$app" "$app"
		fail=1
		continue
	fi
	gh_state="$(bash "$GH" state --tag "$tag")"
	onchain="$(ccall "$REGISTRY" 'releaseByVersion(bytes32,string)(bytes32)' "$appid" "$version" | lower)"
	if [ "$onchain" != "$zero" ]; then
		if [ "$gh_state" = published ]; then
			log "ok   $app $version is released (onchain $onchain, $tag); nothing to do"
		else
			printf '::error title=release-incomplete::%s %s is published onchain (%s) but GitHub Release %s is %s\n' "$app" "$version" "$onchain" "$tag" "$gh_state"
			fail=1
		fi
		continue
	fi
	if [ "$gh_state" != none ]; then
		who="$(bash "$GH" author --tag "$tag")" || die "cannot read the author of GitHub Release $tag"
		if [ "$who" != "github-actions[bot]" ]; then
			printf '::error title=release-not-ci::GitHub Release %s (%s) was created by %s, not by the release workflow; check where it came from and delete it, or bump release_version\n' "$tag" "$gh_state" "$who"
			fail=1
			continue
		fi
	fi
	if [ "$gh_state" = published ]; then
		# supply-1: a release the publish job did not finish, or one planted under the tag. Not a normal plan.
		printf '::warning title=published-not-onchain::%s %s: GitHub Release %s is published but absent onchain; the publish job uses it only if its bundle is the bundle that run built, or is signed by release.yml on main\n' "$app" "$version" "$tag"
		gh_state=published-not-onchain
	fi
	log "plan $app $version ($tag, GitHub Release: $gh_state)"
	entries+=("$(jq -c --arg s "$gh_state" '. + {githubRelease: $s}' <<<"$p")")
done
[ "$fail" = 0 ] || die "cannot release (see the errors above)"
if [ "${#entries[@]}" -eq 0 ]; then
	jq -n '{include: [], count: 0}' >"$OUT"
else
	printf '%s\n' "${entries[@]}" | jq -s '{include: ., count: length}' >"$OUT"
fi
log "releases to run: $(jq -r '[.include[].app] | join(", ") | if . == "" then "none" else . end' "$OUT")"
