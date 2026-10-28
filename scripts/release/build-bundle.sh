#!/usr/bin/env bash
# Build an app's release bundle with `sealed release build` and check it two ways before it is signed:
#   1. catalog/tools/release builds the same bundle with the composer library directly; both tars must be
#      byte-identical (this is the maintainer's reproducibility promise, spec 6.9);
#   2. the composer's catalog lint runs on the bundle in release mode (licenses per D-021 and D-050 with
#      license_exceptions, digests, telemetry, egress, SBOM package licenses), and any error fails.
#
#   scripts/release/build-bundle.sh --app <id> --sbom-dir <dir> --scan-dir <dir> --out <file.bundle.tar> --info <info.json>
#
# The CLI comes from SEALED_CLI, else from `go build ./cli/cmd/sealed`. Its interface (cli/ owns it):
#   sealed release build <app> --catalog catalog/apps --sbom-dir <dir> --scan-dir <dir> --out <file>
# Until the CLI exists the script fails, unless ALLOW_MISSING_SEALED_CLI=1 (then the composer-built bundle
# is used alone and a warning says so).

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

APP="" SBOM="" SCAN="" OUT="" INFO=""
while [ $# -gt 0 ]; do
	case "$1" in
	--app) APP="${2:-}"; shift 2 ;;
	--sbom-dir) SBOM="${2:-}"; shift 2 ;;
	--scan-dir) SCAN="${2:-}"; shift 2 ;;
	--out) OUT="${2:-}"; shift 2 ;;
	--info) INFO="${2:-}"; shift 2 ;;
	*) die "unknown argument: $1" 2 ;;
	esac
done
[ -n "$APP" ] && [ -d "$SBOM" ] && [ -d "$SCAN" ] && [ -n "$OUT" ] && [ -n "$INFO" ] ||
	die "usage: build-bundle.sh --app <id> --sbom-dir <dir> --scan-dir <dir> --out <file> --info <info.json>" 2
need jq

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sealed-bundle.XXXXXX")"
add_cleanup "rm -rf '$WORK'"

# Reference build with the composer library.
release_tool bundle --app "$APP" --sbom-dir "$SBOM" --scan-dir "$SCAN" --out "$WORK/reference.tar" >"$WORK/info.json"
log "ok   composer build: bundleHash $(jq -r .bundleHash "$WORK/info.json")"

CLI="${SEALED_CLI:-}"
if [ -z "$CLI" ] && [ -d "$RELEASE_ROOT/cli/cmd/sealed" ]; then
	need go
	(cd "$RELEASE_ROOT" && go build -o "$WORK/sealed" ./cli/cmd/sealed) || die "cannot build cli/cmd/sealed"
	CLI="$WORK/sealed"
fi
if [ -n "$CLI" ]; then
	(cd "$RELEASE_ROOT" && "$CLI" release build "$APP" --catalog catalog/apps --sbom-dir "$SBOM" --scan-dir "$SCAN" --out "$WORK/cli.tar") >&2 ||
		die "sealed release build $APP failed"
	cmp -s "$WORK/cli.tar" "$WORK/reference.tar" ||
		die "sealed release build $APP and the composer library built different bundles ($(shasum -a 256 "$WORK/cli.tar" | cut -c1-16) vs $(jq -r .bundleHash "$WORK/info.json" | cut -c3-18))"
	log "ok   sealed release build $APP reproduces the bundle byte for byte"
elif [ "${ALLOW_MISSING_SEALED_CLI:-0}" = 1 ]; then
	log "warn sealed release build is not available (no cli/cmd/sealed); using the composer build alone"
else
	die "sealed release build is not available (no cli/cmd/sealed and no SEALED_CLI); set ALLOW_MISSING_SEALED_CLI=1 to release without it"
fi

# Release-mode catalog lint on the bundle itself.
if [ -n "${SEALED_COMPOSE_BIN:-}" ]; then
	compose_cmd=("$SEALED_COMPOSE_BIN")
else
	need go
	(cd "$RELEASE_ROOT" && go build -o "$WORK/sealed-compose" ./runtime/composer/cmd/sealed-compose) || die "cannot build sealed-compose"
	compose_cmd=("$WORK/sealed-compose")
fi
"${compose_cmd[@]}" lint --bundle "$WORK/reference.tar" --require-sbom --json >"$WORK/lint.json" || true
jq -e 'type == "array"' "$WORK/lint.json" >/dev/null || die "the composer lint did not run on the bundle"
release_tool lint-gate --findings "$WORK/lint.json" --mode release || die "the bundle fails the release lint"

mv "$WORK/reference.tar" "$OUT"
jq --arg f "$OUT" '.file = $f' "$WORK/info.json" >"$INFO"
log "ok   $(basename "$OUT"): $(jq -r '"\(.slug) \(.version) releaseId \(.releaseId)"' "$INFO")"
