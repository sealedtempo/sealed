# syntax=docker/dockerfile:1.7
# sealed-agent image. Build from the repository root:
#   docker build -f runtime/agent/Dockerfile -t sealed-agent .
#
# The agent starts as root because LUKS (cryptsetup open/luksFormat), dmsetup, mkfs and mount need
# it (the composer grants this one container CAP_SYS_ADMIN and the data-disk device). After the
# disk is mounted and the tmpfs secrets are written it forks the small Caddy admin helper (which
# keeps root to reach the root-only admin socket) and drops to uid/gid 10001 (SEALED_RUN_AS).
#
# Not built in this workstream (no Docker daemon): the pins below are from packages.debian.org
# for bookworm and must be confirmed by the CI image build.

# node:24.22.1-bookworm-slim, index digest pinned 2026-10-28 (docs/notes/crawlee.md).
ARG NODE_IMAGE=node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c

FROM ${NODE_IMAGE} AS build
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY runtime/agent/package.json runtime/agent/
RUN corepack install && pnpm install --frozen-lockfile --filter "@sealed/agent..."
COPY config/defaults.yaml config/defaults.yaml
COPY packages/core packages/core
COPY runtime/agent runtime/agent
RUN pnpm --filter @sealed/core build \
 && pnpm --filter @sealed/agent build \
 && pnpm --filter @sealed/agent deploy --prod --legacy /out

FROM ${NODE_IMAGE} AS runtime
# Debian packages come from a dated snapshot so the pinned versions stay installable.
ARG DEBIAN_SNAPSHOT=20261027T000000Z
RUN printf '%s\n' \
      "Types: deb" \
      "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" \
      "Suites: bookworm bookworm-updates" \
      "Components: main" \
      "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg" \
      "" \
      "Types: deb" \
      "URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}" \
      "Suites: bookworm-security" \
      "Components: main" \
      "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg" \
      > /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
      cryptsetup-bin=2:2.6.1-4~deb12u2 \
      libcryptsetup12=2:2.6.1-4~deb12u2 \
      dmsetup=2:1.02.185-2 \
      libdevmapper1.02.1=2:1.02.185-2 \
      e2fsprogs=1.47.0-2+b2 \
      mount=2.38.1-5+deb12u3 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 sealed \
 && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin sealed

WORKDIR /app
COPY --from=build /out /app
COPY config/defaults.yaml /app/config/defaults.yaml

# DM_DISABLE_UDEV: there is no udev in the container, so libdevmapper creates /dev/mapper nodes itself.
ENV NODE_ENV=production \
    NODE_USE_ENV_PROXY=1 \
    DM_DISABLE_UDEV=1 \
    SEALED_DEFAULTS_PATH=/app/config/defaults.yaml \
    SEALED_RUN_AS=10001:10001 \
    PORT=7070

LABEL org.opencontainers.image.title="sealed-agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Sealed in-VM agent: key release, disk unlock, secrets, evidence, metering and fee payments"

EXPOSE 7070
HEALTHCHECK --interval=5s --timeout=4s --start-period=10s --retries=3 CMD ["node", "/app/dist/src/healthcheck.js"]
ENTRYPOINT ["node", "/app/dist/main.js"]
