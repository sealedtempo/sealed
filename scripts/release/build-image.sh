#!/usr/bin/env bash
# Build one catalog or sidecar image reproducibly for linux/amd64 (D-028), optionally push it, and check
# that a second build without cache gives the same digest.
#
#   scripts/release/build-image.sh --entry <build-matrix entry JSON> --out <result.json> \
#     [--push] [--tag <tag>] [--verify-reproducible] [--commit <sha>]
#
# The entry is one element of `catalog/tools/release images --format build-matrix` (name, dir, context,
# dockerfile, repository, nonreproducible). Reproducibility settings, the same for every image:
#   - SOURCE_DATE_EPOCH=0, passed as a build arg too, and rewrite-timestamp=true, so file times and the image
#     creation time are fixed and the digest depends only on the inputs;
#   - no buildx attestations in the image (--provenance=false --sbom=false; the release attaches SBOMs and
#     provenance separately), OCI media types, gzip compression;
#   - the Dockerfile frontend pinned by digest (BUILDKIT_SYNTAX), and BuildKit itself pinned by the workflow's
#     builder (docker/setup-buildx-action driver-opts image=moby/buildkit:<version>@<digest>).
# --push pushes <repository>:<tag> (default tag: git-<12 hex of --commit>); without it the image goes to an
# OCI archive under the work dir. --verify-reproducible rebuilds with --no-cache into an OCI archive and
# compares the manifest digests; a mismatch fails unless the entry carries a nonreproducible reason.
#
# Writes the result (catalog/tools/release BuildResult) to --out. Needs docker with buildx.

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

# docker/dockerfile:1.7.1, the frontend the catalog Dockerfiles name with `# syntax=docker/dockerfile:1.7`.
DOCKERFILE_FRONTEND="docker.io/docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
PLATFORM=linux/amd64

ENTRY="" OUT="" PUSH=0 TAG="" VERIFY=0 COMMIT="${GITHUB_SHA:-}"
while [ $# -gt 0 ]; do
	case "$1" in
	--entry) ENTRY="${2:-}"; shift 2 ;;
	--out) OUT="${2:-}"; shift 2 ;;
	--push) PUSH=1; shift ;;
	--tag) TAG="${2:-}"; shift 2 ;;
	--verify-reproducible) VERIFY=1; shift ;;
	--commit) COMMIT="${2:-}"; shift 2 ;;
	*) die "unknown argument: $1" 2 ;;
	esac
done
[ -n "$ENTRY" ] && [ -n "$OUT" ] || die "usage: build-image.sh --entry <json> --out <result.json> [--push] [--verify-reproducible]" 2
need docker
need jq
get() { jq -r --arg k "$1" '.[$k] // empty' <<<"$ENTRY"; }
NAME="$(get name)"
DIR="$(get dir)"
CONTEXT="$(get context)"
DOCKERFILE="$(get dockerfile)"
REPO="$(get repository)"
NONREPRO="$(get nonreproducible)"
[[ "$NAME" =~ ^[a-z][a-z0-9-]*$ ]] || die "bad image name $NAME" 2
[ -n "$DIR" ] && [ -n "$CONTEXT" ] && [ -n "$DOCKERFILE" ] && [ -n "$REPO" ] || die "entry needs dir, context, dockerfile and repository" 2
[ -f "$RELEASE_ROOT/$DOCKERFILE" ] || die "$DOCKERFILE does not exist"
if [ -z "$TAG" ]; then
	[[ "$COMMIT" =~ ^[0-9a-f]{12,40}$ ]] || die "--tag or a --commit sha is needed to tag the image" 2
	TAG="git-${COMMIT:0:12}"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sealed-build.XXXXXX")"
add_cleanup "rm -rf '$WORK'"
export SOURCE_DATE_EPOCH=0

build() { # build <metadata file> <output spec> [extra args...]
	local meta="$1" output="$2"
	shift 2
	docker buildx build \
		--platform "$PLATFORM" \
		--file "$RELEASE_ROOT/$DOCKERFILE" \
		--build-arg SOURCE_DATE_EPOCH=0 \
		--build-arg "BUILDKIT_SYNTAX=$DOCKERFILE_FRONTEND" \
		--provenance=false --sbom=false \
		--metadata-file "$meta" \
		--output "$output" \
		"$@" \
		"$RELEASE_ROOT/$CONTEXT"
}
digest_of() {
	local d
	d="$(jq -r '."containerimage.digest" // empty' "$1")"
	[[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || die "no image digest in the buildx metadata ($1)"
	printf '%s' "$d"
}

common="rewrite-timestamp=true,oci-mediatypes=true,compression=gzip,force-compression=true"
if [ "$PUSH" = 1 ]; then
	log "build $NAME from $DOCKERFILE (context $CONTEXT) and push $REPO:$TAG"
	build "$WORK/meta.json" "type=image,name=$REPO:$TAG,push=true,$common"
else
	log "build $NAME from $DOCKERFILE (context $CONTEXT) into an OCI archive"
	build "$WORK/meta.json" "type=oci,dest=$WORK/image.tar,$common"
fi
DIGEST="$(digest_of "$WORK/meta.json")"
log "ok   $NAME $DIGEST"
if [ "$PUSH" = 1 ]; then
	need crane
	got="$(crane digest "$REPO@$DIGEST")" || die "$REPO@$DIGEST is not in the registry after the push"
	[ "$got" = "$DIGEST" ] || die "the registry serves $got for $REPO@$DIGEST"
fi

REPRO=null REBUILD=""
if [ "$VERIFY" = 1 ]; then
	log "rebuild $NAME without cache to check the digest"
	build "$WORK/meta2.json" "type=oci,dest=$WORK/rebuild.tar,$common" --no-cache
	REBUILD="$(digest_of "$WORK/meta2.json")"
	if [ "$REBUILD" = "$DIGEST" ]; then
		REPRO=true
		log "ok   reproducible: the rebuild gives $REBUILD"
	else
		REPRO=false
		if [ -n "$NONREPRO" ]; then
			log "warn not reproducible (rebuild gave $REBUILD), accepted in images.yaml: $NONREPRO"
		else
			log "error: not reproducible: the build gave $DIGEST, the rebuild $REBUILD"
		fi
	fi
fi

jq -n --arg name "$NAME" --arg dir "$DIR" --arg repo "$REPO" --arg tag "$TAG" --arg digest "$DIGEST" --arg commit "$COMMIT" \
	--argjson repro "$REPRO" --arg rebuild "$REBUILD" \
	'{name: $name, dir: $dir, repository: $repo, tag: $tag, digest: $digest, commit: $commit}
	 + (if $repro == null then {} else {reproducible: $repro, rebuildDigest: $rebuild} end)' >"$OUT"
if [ "$REPRO" = false ] && [ -z "$NONREPRO" ]; then
	exit 4
fi
