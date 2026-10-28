#!/usr/bin/env bash
# Rewrites the Go module path once the public repo name is known.
# Usage: scripts/set-module-path.sh github.com/<owner>/<repo>
set -euo pipefail
new="${1:?usage: $0 github.com/<owner>/<repo>}"
old="$(go list -m)"
[ "$old" = "$new" ] && exit 0
go mod edit -module "$new"
grep -rl --include='*.go' "$old" . | xargs sed -i.bak "s#${old}#${new}#g"
find . -name '*.go.bak' -delete
go build ./...
