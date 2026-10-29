# syntax=docker/dockerfile:1.7
# sealed-mpp-payer sidecar (apps network .5, port 8090). Its digest is pinned in
# runtime/composer/runtime-images.json by the runtime image workflow.
# Build context: the repository root. Target platform: linux/amd64.
#   docker build -f runtime/mpp-payer/Dockerfile .

FROM --platform=linux/amd64 docker.io/library/node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c AS build
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 CI=1
RUN corepack enable && corepack prepare pnpm@10.33.2 --activate
WORKDIR /src
COPY . .
RUN pnpm install --frozen-lockfile --filter @sealed/mpp-payer... \
 && pnpm --filter @sealed/mpp-payer build \
 && pnpm --filter @sealed/mpp-payer deploy --legacy --prod /out \
 && test -f /out/dist/main.js \
 && rm -rf /out/test /out/src

FROM --platform=linux/amd64 docker.io/library/node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
ENV NODE_ENV=production \
    NODE_USE_ENV_PROXY=1 \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    DO_NOT_TRACK=1
COPY --from=build --chown=root:root /out /app
# Payer state: the day's debits, the channel journal (descriptors for deposit recovery) and the
# stored session channel. In the container's writable layer a restart keeps it; a persistent mount
# here (owned by node, uid 1000) also keeps it across image updates and VM replacement. After
# SIGTERM the payer needs up to 38 s (cooperative channel close), so stop_grace_period >= 45s.
RUN install -d -o node -g node -m 0700 /var/lib/sealed-mpp-payer
WORKDIR /app
USER node
EXPOSE 8090
HEALTHCHECK --interval=10s --timeout=3s --retries=6 CMD ["node", "-e", "fetch('http://127.0.0.1:8090/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
LABEL org.opencontainers.image.source="https://github.com/sealedtempo/sealed" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="sealed-mpp-payer"
ENTRYPOINT ["node"]
CMD ["/app/dist/main.js"]
