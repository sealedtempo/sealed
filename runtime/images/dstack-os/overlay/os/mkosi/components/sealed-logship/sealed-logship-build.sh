#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Build sealed-logship (Sealed debug variant only) into a rootfs staging tree.
# The program uses only the Go standard library and its go.mod has no
# requirements, so nothing is downloaded: GOPROXY=off and GOTOOLCHAIN=local
# (exported by mkosi.build) keep the pinned toolchain the only input.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
SELF="$ROOT/os/mkosi/components/sealed-logship"
STAGE=$(realpath -m "${1:?rootfs staging tree required}")
mkdir -p "$STAGE/usr/bin" "$STAGE/usr/lib/systemd/system" \
  "$STAGE/usr/lib/systemd/system-preset"

export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOPROXY=off
(cd "$ROOT/os/sealed/logship" && \
  go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
    -o "$STAGE/usr/bin/sealed-logship" .)
# The binary links the Go standard library (BSD-3-Clause), whose notice and
# patent grant a binary redistribution must carry. GOROOT is the official
# toolchain tarball, which has both files; they must be the upstream texts
# byte for byte (the same sha256 as in runtime/envexec/Dockerfile; unchanged
# from go1.26.2 to go1.27.3).
goroot=$(go env GOROOT)
echo "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad  $goroot/LICENSE" | sha256sum -c -
echo "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc  $goroot/PATENTS" | sha256sum -c -
install -Dm0644 "$goroot/LICENSE" "$STAGE/usr/share/licenses/sealed-logship/go/LICENSE"
install -Dm0644 "$goroot/PATENTS" "$STAGE/usr/share/licenses/sealed-logship/go/PATENTS"
install -m0644 "$SELF/sealed-logship.service" \
  "$STAGE/usr/lib/systemd/system/sealed-logship.service"
# The preset name must contain "dstack": mkosi.postinst deletes every other
# preset file so that 99-dstack-default.preset's "disable *" stays terminal.
install -m0644 "$SELF/82-dstack-sealed-debug.preset" \
  "$STAGE/usr/lib/systemd/system-preset/82-dstack-sealed-debug.preset"
find "$STAGE" -print0 | xargs -0r touch --no-dereference --date="@${SOURCE_DATE_EPOCH:?}"
