# syntax=docker/dockerfile:1.7
# Sealed inference relay: the mppx front (dist/main.js) and the provider verification
# sidecars (dist/sidecar-main.js <tinfoil|phala|nearai>) from runtime/relay.
# Build context: the repository root. Target platform: linux/amd64.
#   docker build -f catalog/apps/inference-relay/images/relay/Dockerfile .

FROM --platform=linux/amd64 docker.io/library/node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c AS build
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 CI=1
RUN corepack enable && corepack prepare pnpm@10.33.2 --activate
WORKDIR /src
COPY . .
# pnpm stamps .modules.yaml and the workspace state file with the install time; they are removed so a
# no-cache rebuild gives the same digest (D-028).
RUN pnpm install --frozen-lockfile --filter @sealed/relay... \
 && pnpm --filter @sealed/relay build \
 && pnpm --filter @sealed/relay deploy --legacy --prod /out \
 && test -f /out/dist/main.js && test -f /out/dist/sidecar-main.js && test -f /out/config/prices.json \
 && rm -rf /out/test /out/src /out/tmp \
 && rm -f /out/node_modules/.modules.yaml /out/node_modules/.pnpm-workspace-state*.json

FROM --platform=linux/amd64 docker.io/library/node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
ENV NODE_ENV=production \
    NODE_USE_ENV_PROXY=1 \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    DO_NOT_TRACK=1
COPY --from=build --chown=root:root /out /app
WORKDIR /app
USER node
EXPOSE 8080 8100
LABEL org.opencontainers.image.source="https://github.com/sealedtempo/sealed" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="sealed inference relay"
ENTRYPOINT ["node"]
CMD ["/app/dist/main.js"]
