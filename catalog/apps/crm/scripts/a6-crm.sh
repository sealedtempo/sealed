#!/usr/bin/env bash
# A6 acceptance helper for crm: create an account, a contact and an opportunity through
# EspoCRM's REST API with an API key, and check the links between them. The work is done by
# a6-crm.mjs (Node 22+, no dependencies); see its header for the environment variables.
#
#   CRM_URL=https://crm.34-1-2-3.sslip.io API_KEY_FILE=./api-key.json GATE_BASIC=sealed:... \
#     catalog/apps/crm/scripts/a6-crm.sh > a6-ids.json
#   # A11, after the reboot:
#   CRM_URL=... API_KEY_FILE=... GATE_BASIC=... catalog/apps/crm/scripts/a6-crm.sh --check a6-ids.json
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v node >/dev/null 2>&1; then
  echo "a6-crm: node 22 or newer is required" >&2
  exit 2
fi
major="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$major" -lt 22 ]; then
  echo "a6-crm: node 22 or newer is required (found $(node --version))" >&2
  exit 2
fi
exec node "$here/a6-crm.mjs" "$@"
