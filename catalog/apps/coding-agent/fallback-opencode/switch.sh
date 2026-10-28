#!/usr/bin/env bash
# Switch the coding-agent catalog app from OpenHands (default release) to the OpenCode fallback.
# Copies this directory's release files over the app's, copies the image build context to
# images/opencode, and regenerates compose.fragment.yaml. This directory stays as the source.
# To go back to OpenHands, revert the commit that contains the switch.
#
#   catalog/apps/coding-agent/fallback-opencode/switch.sh
# Then: build the opencode image, pin its digest in manifest.yaml, run the tests, open a PR.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
app="$(cd "$here/.." && pwd)"

if grep -q '^  - name: opencode$' "$app/manifest.yaml"; then
  echo "coding-agent already uses OpenCode" >&2
  exit 1
fi
for f in manifest.yaml compose.fragment.in.yaml egress.yaml waivers.yaml; do
  cp "$here/$f" "$app/$f"
done
mkdir -p "$app/images"
rm -rf "$app/images/opencode"
cp -R "$here/images/opencode" "$app/images/opencode"
python3 "$app/tools/build_fragment.py"
echo "coding-agent now uses the OpenCode fallback (route code -> coding-agent-server:4096)."
