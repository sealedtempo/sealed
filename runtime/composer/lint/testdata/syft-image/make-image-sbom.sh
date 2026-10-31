#!/usr/bin/env bash
# Builds a small synthetic container image whose file layout copies the paths the catalog manifests
# exclude (and near misses that must not match), scans it with syft as the release pipeline does
# for lint (sealed_syft_files of scripts/release/syft-env.sh, as scripts/release/scan-image.sh
# runs it), and writes the SPDX JSON. Needs syft, crane and Go with go-ethereum v1.17.10 in the
# module cache; no docker daemon. syft reads Go module licenses from that cache and asks
# proxy.golang.org only for modules it lacks.
#
#   bash runtime/composer/lint/testdata/syft-image/make-image-sbom.sh . runtime/composer/lint/testdata/syft-image/image.spdx.json
#
# The SBOM changes with the syft and Go versions (the committed one: syft 1.55.0, Go 1.27.3). The
# tests read only paths, names, purls and licenses, so regenerate it when a manifest gains a
# pattern that no path here matches: add a positive path and a near miss below.
set -euo pipefail
repo=$(cd "$1" && pwd)
out=$2
work=$(mktemp -d "${TMPDIR:-/tmp}/lint-image.XXXXXX")
trap 'rm -rf "$work"' EXIT
r=$work/rootfs
mkdir -p "$r"

put() { # put <path> [content]
  mkdir -p "$r/$(dirname "$1")"
  printf '%s\n' "${2:-x}" >"$r/$1"
}

# --- OS: Debian 13 with a dpkg database --------------------------------------------------------
put etc/os-release 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
ID=debian'
status=$r/var/lib/dpkg/status
md5sum_of() { if command -v md5sum >/dev/null; then md5sum "$1" | cut -d' ' -f1; else md5 -q "$1"; fi; }
mkdir -p "$r/var/lib/dpkg/info"
deb() { # deb <name> <version> <copyright license ids...> -- <owned files...>
  local name=$1 version=$2; shift 2
  local lics=()
  while [ "$1" != "--" ]; do lics+=("$1"); shift; done
  shift
  cat >>"$status" <<EOF
Package: $name
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 100
Maintainer: Debian <debian@example.org>
Architecture: amd64
Version: $version
Description: $name
 synthetic package for the lint fixture

EOF
  : >"$r/var/lib/dpkg/info/$name.list"
  : >"$r/var/lib/dpkg/info/$name.md5sums"
  for f in "$@"; do
    put "${f#/}" "$name"
    echo "$f" >>"$r/var/lib/dpkg/info/$name.list"
    printf '%s  %s\n' "$(md5sum_of "$r$f")" "${f#/}" >>"$r/var/lib/dpkg/info/$name.md5sums"
  done
  if [ ${#lics[@]} -gt 0 ]; then
    local c="$r/usr/share/doc/$name/copyright"
    mkdir -p "$(dirname "$c")"
    printf 'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: %s\n\n' "$name" >"$c"
    for l in "${lics[@]}"; do printf 'Files: *\nCopyright: someone\nLicense: %s\n\n' "$l" >>"$c"; done
    echo "/usr/share/doc/$name/copyright" >>"$r/var/lib/dpkg/info/$name.list"
  fi
}
deb libc6 2.41-12 LGPL-2.1+ GPL-2 -- /usr/lib/x86_64-linux-gnu/libc.so.6
# Redis from packages.redis.io, as in the upstream ToolJet image: no machine-readable copyright.
deb redis-server 6:8.2.1-1rl1~trixie1 -- /usr/bin/redis-server /usr/bin/redis-check-aof /usr/bin/redis-check-rdb \
  /etc/redis/redis.conf /usr/lib/redis/modules/redisearch.so
deb redis-tools 6:8.2.1-1rl1~trixie1 -- /usr/bin/redis-cli /usr/bin/redis-benchmark
# PHP 8.4 as in the EspoCRM image: PHP-3.01 and the Zend Engine License 2.00 (license audit F11).
deb php8.4-common 8.4.11-1 PHP-3.01 Zend-2.0 -- /usr/lib/php/20240924/opcache.so
# Ewe (ee) translations owned by an OS package: not an open-core ee/ directory.
deb iso-codes 4.18.0-1 LGPL-2.1+ -- /usr/share/locale/ee/LC_MESSAGES/iso_639-2.mo /usr/share/iso-codes/json/iso_639-2.json
deb git 1:2.47.3-0+deb13u1 GPL-2 -- /usr/bin/git
deb fonts-dejavu-core 2.37-8 bitstream-vera -- /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf

# --- Python site-packages (LiteLLM images) -----------------------------------------------------
sp=app/.venv/lib/python3.13/site-packages
pydist() { # pydist <dist-info dir name> <Name> <Version> <license line or ""> <files relative to site-packages...>
  local dist=$1 name=$2 version=$3 lic=$4; shift 4
  local d=$sp/$dist
  local meta="Metadata-Version: 2.4
Name: $name
Version: $version"
  [ -n "$lic" ] && meta="$meta
$lic"
  put "$d/METADATA" "$meta"
  put "$d/WHEEL" "Wheel-Version: 1.0"
  : >"$r/$d/RECORD"
  for f in "$@" "$dist/METADATA" "$dist/WHEEL" "$dist/RECORD"; do
    [ -e "$r/$sp/$f" ] || put "$sp/$f" "# $name"
    echo "$f,," >>"$r/$d/RECORD"
  done
}
pydist litellm-1.106.5.dist-info litellm 1.106.5 "License-Expression: MIT" \
  litellm/__init__.py litellm/proxy/enterprise_billing/__init__.py litellm/proxy/proxy_server.py
pydist litellm_enterprise-0.1.20.dist-info litellm-enterprise 0.1.20 "License-Expression: LicenseRef-Proprietary" \
  litellm_enterprise/__init__.py litellm_enterprise/enterprise_callbacks/send_emails/base_email.py
# No license metadata in the wheels (license audit F5).
pydist google_crc32c-1.8.0.dist-info google-crc32c 1.8.0 "" google_crc32c/__init__.py
pydist aurelio_sdk-0.0.19.dist-info aurelio-sdk 0.0.19 "" aurelio_sdk/__init__.py
pydist llm_sandbox-0.3.39.dist-info llm-sandbox 0.3.39 "" llm_sandbox/__init__.py
# Upstream source copy of the enterprise tree, owned by no package.
put app/enterprise/enterprise_hooks/banned_keywords.py
put app/enterprise/LICENSE.md "BerriAI Enterprise license"
put app/litellm/proxy/enterprise_billing/README.md
# Ollama GPU runners (NVIDIA redistributables) and the CPU runner that stays.
put usr/lib/ollama/cuda_v12/libggml-cuda.so
put usr/lib/ollama/cuda_v13/libggml-cuda.so
put usr/lib/ollama/mlx_cuda_v13/libmlx.so
put usr/lib/ollama/vulkan/libggml-vulkan.so
put usr/lib/ollama/libggml-cpu-haswell.so

# --- npm packages ------------------------------------------------------------------------------
npm() { # npm <dir> <name> <version> <license json or "">
  local lic=""
  [ -n "$4" ] && lic=", \"license\": $4"
  put "$1/package.json" "{\"name\": \"$2\", \"version\": \"$3\"$lic}"
}
npm acp-node/node_modules/@anthropic-ai/claude-agent-sdk @anthropic-ai/claude-agent-sdk 0.2.9 '"SEE LICENSE IN README.md"'
put acp-node/node_modules/@anthropic-ai/claude-agent-sdk/cli.js
npm acp-node/node_modules/@zed-industries/claude-code-acp @zed-industries/claude-code-acp 0.10.0 '"Apache-2.0"'
npm app/node_modules/@playwright/browser-chromium @playwright/browser-chromium 1.62.1 '"Apache-2.0"'
npm app/node_modules/@playwright/browser-firefox @playwright/browser-firefox 1.62.1 '"Apache-2.0"'
npm app/node_modules/idcac-playwright idcac-playwright 0.1.3 '"GPL-3.0-only"'
npm app/node_modules/map-stream map-stream 0.1.0 ""
npm app/node_modules/pause-stream pause-stream 0.0.11 '["MIT", "Apache2"]'
npm app/node_modules/ee-first ee-first 1.1.1 '"MIT"'
npm app/node_modules/@fontsource/inter @fontsource/inter 5.2.8 '"OFL-1.1"'
put app/node_modules/@fontsource/inter/files/inter-latin-400-normal.woff2
# ToolJet CE layout: enterprise ee/ trees (owned by no package) and near misses.
put app/server/ee/licensing/license.service.js
put app/server/dist/ee/licensing/license.service.js
put app/frontend/ee/components/Billing.jsx
put app/frontend/build/ee/billing.js
put app/server/src/modules/free/index.js
put app/server/tree/index.js
put app/server/ee.config.js
put opt/oracle/instantclient_21_10/libclntsh.so.21.1
# Playwright browsers: Chromium (excluded) and Firefox (ships).
put ms-playwright/chromium-1187/chrome-linux/chrome
put ms-playwright/chromium_headless_shell-1187/chrome-linux/headless_shell
put ms-playwright/firefox-1490/firefox/firefox
put root/.cache/ms-playwright/chromium-1187/INSTALLATION_COMPLETE

# --- A Go binary linking go-ethereum and the Prometheus client (key-broker, verifierd, CLI) ------
g=$work/gobin
mkdir -p "$g"
cp "$repo/go.mod" "$repo/go.sum" "$g/"
cat >"$g/main.go" <<'EOF'
package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func main() {
	fmt.Println(metrics.NewCounter().Snapshot().Count(), prometheus.NewRegistry() != nil)
}
EOF
mkdir -p "$r/usr/local/bin"
(cd "$g" && GOPROXY=off GOFLAGS=-mod=mod CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$r/usr/local/bin/sealed-tool" .)

# --- Image and SBOM ----------------------------------------------------------------------------
COPYFILE_DISABLE=1 tar -C "$r" --numeric-owner -cf "$work/layer.tar" .
crane append --oci-empty-base -f "$work/layer.tar" -t sealed.test/lint-fixture:1 -o "$work/image.tar" >/dev/null
# As the release scan lists files for lint (scan-image.sh): the same syft settings and scan call, so
# every file is listed and Go module licenses are read (license audit F5, F6). Only the source and
# its name differ.
# shellcheck source=scripts/release/syft-env.sh
. "$repo/scripts/release/syft-env.sh"
(cd "$work" && sealed_syft_files docker-archive:image.tar --source-name lint-fixture --source-version 1 -o spdx-json=image.spdx.json)
python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); json.dump(d, open(sys.argv[2], "w"), indent=1, sort_keys=True); open(sys.argv[2], "a").write("\n")' \
  "$work/image.spdx.json" "$out"
