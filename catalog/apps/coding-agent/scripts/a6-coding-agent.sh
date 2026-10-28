#!/usr/bin/env bash
# A6 acceptance helper for the coding-agent app: the agent writes a file and runs a test through
# llm-gateway, then we verify the file, rerun the test ourselves and check token usage.
# Needs python3 (standard library only). Run with --help for options; see a6_coding_agent.py.
#
#   A6_URL=https://code.<ip-with-dashes>.sslip.io CODING_AGENT_API_KEY=... SEALED_GATE_PASSWORD=... \
#     catalog/apps/coding-agent/scripts/a6-coding-agent.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$here/a6_coding_agent.py" "$@"
