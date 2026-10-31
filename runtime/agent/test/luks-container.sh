#!/usr/bin/env bash
# Runs the opt-in real-LUKS suite (test/disk.real.test.ts) inside a privileged container made from the agent
# image's base (runtime/agent/Dockerfile NODE_IMAGE), with the agent image's Debian snapshot and package pins, so
# the test meets the cryptsetup, dmsetup, util-linux and e2fsprogs the agent ships. disk.real.test.ts checks
# that the pins below match the Dockerfile.
#
# .github/workflows/agent-luks.yml runs it. A local run (Linux host or VM with the loop, dm_mod and dm_crypt
# modules), from the repository root:
#
#   docker run --rm --privileged -v "$PWD:/src:ro" <NODE_IMAGE from runtime/agent/Dockerfile> \
#     bash /src/runtime/agent/test/luks-container.sh
#
# The source is copied into the container, so the host's node_modules are never used or changed.
set -euo pipefail

src=${SEALED_SRC:-/src}
work=/work
snapshot=20261027T000000Z

printf '%s\n' \
  "Types: deb" \
  "URIs: http://snapshot.debian.org/archive/debian/${snapshot}" \
  "Suites: bookworm bookworm-updates" \
  "Components: main" \
  "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg" \
  "" \
  "Types: deb" \
  "URIs: http://snapshot.debian.org/archive/debian-security/${snapshot}" \
  "Suites: bookworm-security" \
  "Components: main" \
  "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg" \
  > /etc/apt/sources.list.d/debian.sources
apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  cryptsetup-bin=2:2.6.1-4~deb12u2 \
  libcryptsetup12=2:2.6.1-4~deb12u2 \
  dmsetup=2:1.02.185-2 \
  libdevmapper1.02.1=2:1.02.185-2 \
  e2fsprogs=1.47.0-2+b2 \
  mount=2.38.1-5+deb12u3
# losetup, blkid, wipefs and mknod come with the base image (util-linux, coreutils).
cryptsetup --version
losetup --version

mkdir -p "$work"
tar -C "$src" --exclude=node_modules --exclude=.git --exclude=dist --exclude=contracts/dependencies -cf - . | tar -C "$work" -xf -
cd "$work"
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
corepack enable
corepack install
pnpm install --frozen-lockfile --filter "@sealed/agent..."

# As in the agent image: no udev in the container, so libdevmapper creates the /dev/mapper nodes itself.
export DM_DISABLE_UDEV=1
export SEALED_REAL_LUKS=1
cd runtime/agent
pnpm exec vitest run test/disk.real.test.ts
