#!/usr/bin/env bash
# Sign a pushed image digest with cosign keyless signing (GitHub OIDC through Fulcio, logged in Rekor), then
# verify the signature it just made with the identity that catalog.yml and release.yml are meant to check.
# Those jobs do not verify image signatures yet (the supply-3 verify half is not implemented); this script
# only produces and self-checks the signature so that identity is available once they do.
#
#   scripts/release/sign-image.sh --ref <registry>/<name>@sha256:<64 hex>
#
# Runs only in the runtime image workflow on main: the identity is https://github.com/$GITHUB_WORKFLOW_REF and
# must be <owner>/<repo>/.github/workflows/images.yml@refs/heads/main, the identity a consumer is meant to check:
#   cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com \
#     --certificate-identity https://github.com/<owner>/<repo>/.github/workflows/images.yml@refs/heads/main <ref>
# cosign stores the signature in the registry next to the image.

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

REF=""
while [ $# -gt 0 ]; do
	case "$1" in
	--ref) REF="${2:-}"; shift 2 ;;
	*) die "unknown argument: $1" 2 ;;
	esac
done
[[ "$REF" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]] ||
	die "usage: sign-image.sh --ref <registry>/<name>@sha256:<digest> (a digest, never a tag)" 2
[[ "${GITHUB_WORKFLOW_REF:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/images\.yml@refs/heads/main$ ]] ||
	die "images are signed only by .github/workflows/images.yml on main (GITHUB_WORKFLOW_REF is '${GITHUB_WORKFLOW_REF:-}')" 2
IDENTITY="https://github.com/$GITHUB_WORKFLOW_REF"
ISSUER="https://token.actions.githubusercontent.com"
need cosign

log "sign $REF (keyless, identity $IDENTITY)"
cosign sign --yes "$REF" >/dev/null || die "cosign sign failed for $REF"
cosign verify --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$REF" >/dev/null ||
	die "the signature of $REF does not verify for identity $IDENTITY"
log "ok   signed $REF"
