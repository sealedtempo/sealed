#!/usr/bin/env bash
# Copies the repository files the sealed binary embeds into this package, so the
# one binary works outside a checkout (Cloud Shell included). drift_test.go fails
# when a copy differs from its source; rerun this script (go generate) then.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"

cp "$root/config/defaults.yaml" "$here/defaults.yaml"
cp "$root/contracts/deployments/tempo-mainnet.json" "$here/tempo-mainnet.json"
mkdir -p "$here/abi"
for c in PlatformRegistry AppRegistry DeploymentRegistry; do
  cp "$root/contracts/abi/$c.json" "$here/abi/$c.json"
done

src="$root/infra/terraform/customer-bootstrap"
dst="$here/tfmodule"
rm -rf "$dst"
mkdir -p "$dst"
(
  cd "$src"
  find . -type f \( -name '*.tf' -o -name '*.tftest.hcl' -o -name '.terraform.lock.hcl' -o -name 'README.md' \) \
    -not -path './.terraform/*' -not -path '*/.terraform/*' | LC_ALL=C sort | while read -r f; do
      mkdir -p "$dst/$(dirname "$f")"
      cp "$f" "$dst/$f"
    done
)
