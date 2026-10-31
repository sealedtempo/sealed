#!/usr/bin/env bash
# SBOM and vulnerability gate for one image (spec 6.8): a Syft SBOM (SPDX JSON), a Grype scan of the same
# Syft run, and the waiver gate, which fails on any critical finding that waivers.yaml does not list with a valid,
# unexpired waiver.
#
#   scripts/release/scan-image.sh --image <name> --ref <registry/repo@sha256:...> --waivers <waivers.yaml> \
#     --out <dir> [--source registry|oci-archive] [--archive <image.tar>]
#
# Writes <out>/sbom/<name>.spdx.json, <out>/files/<name>.spdx.json, <out>/scan/<name>.json (grype -o json)
# and <out>/summary/<name>.summary.json (catalog/tools/release ScanSummary). The SBOM and scan files are the
# ones a release bundle carries. files/ is a second Syft SBOM that lists every file of the image, for the
# lint's excluded-path check; it does not ship (syft-env.sh says why). Exit code 5 means the waiver gate
# failed (the files are still written). Syft runs with the settings of syft-env.sh (Go module licenses filled
# in), the same ones the lint fixture is made with. Syft and Grype update checks are switched off.

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=scripts/release/syft-env.sh
. "$(dirname "$0")/syft-env.sh"

IMAGE="" REF="" WAIVERS="" OUTDIR="" SOURCE=registry ARCHIVE=""
while [ $# -gt 0 ]; do
	case "$1" in
	--image) IMAGE="${2:-}"; shift 2 ;;
	--ref) REF="${2:-}"; shift 2 ;;
	--waivers) WAIVERS="${2:-}"; shift 2 ;;
	--out) OUTDIR="${2:-}"; shift 2 ;;
	--source) SOURCE="${2:-}"; shift 2 ;;
	--archive) ARCHIVE="${2:-}"; shift 2 ;;
	*) die "unknown argument: $1" 2 ;;
	esac
done
[ -n "$IMAGE" ] && [ -n "$WAIVERS" ] && [ -n "$OUTDIR" ] || die "usage: scan-image.sh --image <name> --ref <ref@digest> --waivers <file> --out <dir>" 2
need syft
need grype
export GRYPE_CHECK_FOR_APP_UPDATE=false
case "$SOURCE" in
registry)
	[[ "$REF" =~ ^[a-z0-9.-]+(:[0-9]+)?/[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]] || die "--ref must be pinned by digest: $REF" 2
	src="registry:$REF"
	;;
oci-archive)
	[ -f "$ARCHIVE" ] || die "--archive is required with --source oci-archive" 2
	src="oci-archive:$ARCHIVE"
	;;
*) die "--source must be registry or oci-archive" 2 ;;
esac

mkdir -p "$OUTDIR/sbom" "$OUTDIR/files" "$OUTDIR/scan" "$OUTDIR/summary"
sbom="$OUTDIR/sbom/$IMAGE.spdx.json"
files="$OUTDIR/files/$IMAGE.spdx.json"
scan="$OUTDIR/scan/$IMAGE.json"
summary="$OUTDIR/summary/$IMAGE.summary.json"

# One Syft run writes the SPDX SBOM that ships and a Syft JSON SBOM for Grype, which keeps the distro
# details Grype needs to match OS packages.
work="$(mktemp -d "${TMPDIR:-/tmp}/sealed-scan.XXXXXX")"
add_cleanup "rm -rf '$work'"
log "sbom $IMAGE: syft $src"
sealed_syft_sbom "$src" -o "spdx-json=$sbom" -o "syft-json=$work/syft.json" || die "$IMAGE: syft failed"
log "files $IMAGE: syft $src"
sealed_syft_files "$src" -o "spdx-json=$files" || die "$IMAGE: syft failed (file listing)"
for f in "$sbom" "$files"; do
	jq -e '.spdxVersion and (.packages | type == "array")' "$f" >/dev/null || die "$IMAGE: syft did not write an SPDX JSON document ($f)"
done
log "scan $IMAGE: grype"
grype "sbom:$work/syft.json" -o json -q >"$scan" || die "$IMAGE: grype failed"
jq -e '.matches | type == "array"' "$scan" >/dev/null || die "$IMAGE: grype did not write a JSON report"

rm -f "$summary"
if release_tool waivers check --file "$WAIVERS" --image "$IMAGE" --scan "$scan" --summary "$summary" >/dev/null; then
	log "ok   $IMAGE: no critical finding without a valid waiver"
else
	[ -f "$summary" ] || die "$IMAGE: the waiver gate could not run"
	log "error: $IMAGE has critical findings that $WAIVERS does not waive"
	exit 5
fi
