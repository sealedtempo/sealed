#!/usr/bin/env bash
# make devnet-e2e: build what the devnet runs, then run it (scripts/devnet/src/main.ts).
#
#   scripts/devnet/run.sh [--keep] [--settle-seconds N]
#
# Builds into tmp/devnet/bin (gitignored): the sealed CLI, the key broker dev build (-tags sealeddev),
# sealed-verifierd and sealed-compose. Builds @sealed/core and @sealed/agent, and the platform api from the private
# repo (SEALED_API_DIR, else ../sealed-platform/services/api, else ../platform-integration/services/api). Needs Go,
# Node 22.18+ with pnpm, Foundry (anvil, forge) with contracts/dependencies, and PostgreSQL 17 (PG_BIN).
# Nothing here reads the workspace .env; only anvil's public dev keys sign, on chain 31337.
set -euo pipefail

# Run with a minimal environment, so nothing from the caller's environment (for example a Makefile that included
# the workspace .env with real keys and RPC URLs) reaches forge, anvil or any component.
if [ "${DEVNET_CLEAN_ENV:-}" != 1 ]; then
	exec env -i DEVNET_CLEAN_ENV=1 PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" LANG="${LANG:-C}" \
		${PG_BIN:+PG_BIN="$PG_BIN"} ${SEALED_API_DIR:+SEALED_API_DIR="$SEALED_API_DIR"} \
		${GOCACHE:+GOCACHE="$GOCACHE"} ${GOMODCACHE:+GOMODCACHE="$GOMODCACHE"} ${GOPATH:+GOPATH="$GOPATH"} \
		"$0" "$@"
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/tmp/devnet/bin"
t0=$(date +%s)
log() { printf '[devnet-e2e] %s\n' "$*"; }

for tool in go node pnpm anvil forge jq; do
	command -v "$tool" >/dev/null || { echo "devnet-e2e needs $tool on PATH" >&2; exit 1; }
done
[ -d "$ROOT/contracts/dependencies" ] || { echo "contracts/dependencies is missing: run (cd contracts && forge soldeer install)" >&2; exit 1; }

log "building Go binaries into tmp/devnet/bin"
mkdir -p "$BIN"
(cd "$ROOT" && go build -o "$BIN/sealed" ./cli/cmd/sealed \
	&& go build -tags sealeddev -o "$BIN/key-broker" ./key-broker/cmd/key-broker \
	&& go build -o "$BIN/sealed-verifierd" ./verifier/cmd/sealed-verifierd \
	&& go build -o "$BIN/sealed-compose" ./runtime/composer/cmd/sealed-compose)

log "building @sealed/core and @sealed/agent"
if [ ! -d "$ROOT/node_modules/.pnpm" ] || [ ! -e "$ROOT/scripts/devnet/node_modules/@sealed/agent" ]; then
	(cd "$ROOT" && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 pnpm install --frozen-lockfile)
fi
(cd "$ROOT" && pnpm --filter @sealed/core --filter @sealed/agent build >/dev/null)

API_DIR="${SEALED_API_DIR:-}"
if [ -z "$API_DIR" ]; then
	for d in "$ROOT/../sealed-platform/services/api" "$ROOT/../platform-integration/services/api"; do
		[ -f "$d/package.json" ] && { API_DIR="$(cd "$d" && pwd)"; break; }
	done
fi
[ -n "$API_DIR" ] || { echo "the platform api (services/api of the private repo) was not found; set SEALED_API_DIR" >&2; exit 1; }
log "building the platform api in $API_DIR"
if [ ! -e "$API_DIR/node_modules/@sealed/core" ]; then
	# The api links @sealed/core from the public repo next to it; in a worktree its .pnpmfile.cjs points the link
	# at SEALED_CORE_DIR. The install rewrites that link path in the lockfile, so the committed lockfile is restored.
	(cd "$API_DIR" && SEALED_CORE_DIR="$ROOT/packages/core" pnpm install --ignore-workspace --prefer-offline >/dev/null \
		&& { git checkout -- pnpm-lock.yaml 2>/dev/null || true; })
fi
(cd "$API_DIR" && pnpm build >/dev/null)

log "prerequisites ready in $(( $(date +%s) - t0 )) s"
export SEALED_API_DIR="$API_DIR"
# In the background so a signal to this script reaches the orchestrator, which stops every devnet process.
node "$ROOT/scripts/devnet/src/main.ts" --bin "$BIN" "$@" &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null || true' INT TERM HUP
code=0
wait "$pid" || code=$?
# A trapped signal interrupts the first wait; wait again for the orchestrator's cleanup.
if kill -0 "$pid" 2>/dev/null; then wait "$pid" || code=$?; fi
log "total time including builds: $(( $(date +%s) - t0 )) s (exit $code)"
exit "$code"
