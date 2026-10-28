#!/usr/bin/env bash
# A6 acceptance helper for internal-tools: load the ToolJet UI and create an app through the API
# as the bootstrap admin. The work is done by a6-internal-tools.mjs (Node 22+, no dependencies);
# see its header for the environment variables.
#
#   TOOLS_URL=https://tools.34-1-2-3.sslip.io ADMIN_EMAIL=... ADMIN_PASSWORD=... GATE_BASIC=gate:... \
#     catalog/apps/internal-tools/scripts/a6-internal-tools.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v node >/dev/null 2>&1; then
  echo "a6-internal-tools: node 22 or newer is required" >&2
  exit 2
fi
major="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$major" -lt 22 ]; then
  echo "a6-internal-tools: node 22 or newer is required (found $(node --version))" >&2
  exit 2
fi
exec node "$here/a6-internal-tools.mjs" "$@"
