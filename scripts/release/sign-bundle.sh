#!/usr/bin/env bash
# Sign a release bundle with cosign keyless signing (GitHub OIDC through Fulcio, logged in Rekor) and write
# the .sigstore.json, .sig and .crt assets next to it.
#
#   scripts/release/sign-bundle.sh --bundle <dir>/<appId>-<version>.bundle.tar [--identity <url>]
#
# cosign 3 writes a single Sigstore bundle (signature, certificate and Rekor inclusion proof). The .sig
# (base64 signature) and .crt (PEM certificate) assets of the asset rule (D-046) are extracted from it by
# catalog/tools/release sigstore, which also checks that the bundle signs this file's sha256 and carries a
# Rekor entry. The signature is then verified with the expected identity before anything is uploaded.
# --identity defaults to https://github.com/$GITHUB_WORKFLOW_REF (the release workflow on main).

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

BUNDLE="" IDENTITY=""
while [ $# -gt 0 ]; do
	case "$1" in
	--bundle) BUNDLE="${2:-}"; shift 2 ;;
	--identity) IDENTITY="${2:-}"; shift 2 ;;
	*) die "unknown argument: $1" 2 ;;
	esac
done
[ -f "$BUNDLE" ] || die "usage: sign-bundle.sh --bundle <file.bundle.tar> [--identity <url>]" 2
if [ -z "$IDENTITY" ]; then
	[ -n "${GITHUB_WORKFLOW_REF:-}" ] || die "--identity or GITHUB_WORKFLOW_REF is needed" 2
	IDENTITY="https://github.com/$GITHUB_WORKFLOW_REF"
fi
need cosign
ISSUER="https://token.actions.githubusercontent.com"

log "sign $(basename "$BUNDLE") (keyless, identity $IDENTITY)"
cosign sign-blob --yes --bundle "$BUNDLE.sigstore.json" "$BUNDLE" >/dev/null || die "cosign sign-blob failed"
release_tool sigstore --bundle "$BUNDLE.sigstore.json" --blob "$BUNDLE" --sig "$BUNDLE.sig" --crt "$BUNDLE.crt" >"$BUNDLE.rekor.json" ||
	die "the Sigstore bundle does not match $(basename "$BUNDLE")"
cosign verify-blob --bundle "$BUNDLE.sigstore.json" --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$BUNDLE" >/dev/null ||
	die "the signature does not verify for identity $IDENTITY"
log "ok   signed; Rekor $(jq -r .url "$BUNDLE.rekor.json")"
