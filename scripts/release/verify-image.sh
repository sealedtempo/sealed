#!/usr/bin/env bash
# Check that an image this repository builds (manifest `source: build:...`) carries the cosign keyless
# signature of the runtime image workflow on main, before the image is scanned or released (supply-3):
#
#   scripts/release/verify-image.sh --ref <registry>/<name>@sha256:<digest>
#
# The signature must be for this exact digest, with the certificate identity
# https://github.com/<repo>/.github/workflows/images.yml@refs/heads/main and the GitHub Actions OIDC issuer
# (Fulcio certificate, Rekor entry). A digest pinned by hand, or built by any other workflow or branch, has no
# such signature and fails. <repo> is GH_REPO, else GITHUB_REPOSITORY, else config/defaults.yaml.

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

REF=""
while [ $# -gt 0 ]; do
	case "$1" in
	--ref) REF="${2:-}"; shift 2 ;;
	*) die "unknown argument: $1" 2 ;;
	esac
done
[[ "$REF" =~ ^[a-z0-9.-]+(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$ ]] || die "usage: verify-image.sh --ref <registry>/<name>@sha256:<digest>" 2
need cosign
REPO="${GH_REPO:-${GITHUB_REPOSITORY:-}}"
[ -n "$REPO" ] || REPO="$(defaults_get repo)"
IDENTITY="https://github.com/$REPO/.github/workflows/images.yml@refs/heads/main"
ISSUER="https://token.actions.githubusercontent.com"

if ! cosign verify --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$REF" >/dev/null; then
	printf '::error title=image-signature::%s is not signed by %s; pin only digests that the runtime image workflow built and signed on main\n' "$REF" "$IDENTITY"
	exit 1
fi
log "ok   $REF is signed by $IDENTITY"
