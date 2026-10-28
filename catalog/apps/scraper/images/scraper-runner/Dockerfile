# scraper-runner, Cheerio only (no browser). Same code as the Playwright variant; it reports
# crawler "playwright" as unavailable.
#
# Build from the repository root (the build context needs tsconfig.base.json):
#   docker build -f catalog/apps/scraper/images/scraper-runner/Dockerfile -t scraper-runner .
# Dockerfile.dockerignore next to this file limits the context to the runner sources.
#
# Base: node:24.22.1-bookworm-slim, index digest below.
#   linux/amd64 child: sha256:e1582112fb9f152ed38eefcd712efc93fee1becb519fdfa57574d5e07eaa5e7d

FROM node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c AS build
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 CI=1
RUN npm install --global --ignore-scripts pnpm@10.33.2
WORKDIR /src
COPY tsconfig.base.json ./
COPY catalog/apps/scraper/runner/package.json catalog/apps/scraper/runner/pnpm-lock.yaml catalog/apps/scraper/runner/
WORKDIR /src/catalog/apps/scraper/runner
RUN pnpm install --frozen-lockfile --ignore-workspace --no-optional
COPY catalog/apps/scraper/runner/tsconfig.json catalog/apps/scraper/runner/tsconfig.build.json ./
COPY catalog/apps/scraper/runner/src ./src
RUN pnpm run build
# Production dependencies only, without the optional Playwright packages.
RUN mkdir /app \
 && cp package.json pnpm-lock.yaml /app/ \
 && cd /app \
 && pnpm install --frozen-lockfile --ignore-workspace --prod --no-optional \
 && cp -r /src/catalog/apps/scraper/runner/dist /app/dist

FROM node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
# tini (MIT) as PID 1 forwards signals and reaps children.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini=0.19.0-1+b3 \
 && rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production \
    PORT=8080 \
    HOME=/tmp \
    CRAWLEE_PERSIST_STORAGE=false \
    CRAWLEE_STORAGE_DIR=/tmp/crawlee \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    SCRAPER_CRAWLERS=cheerio
COPY --from=build /app /app
WORKDIR /app
# The node user (uid 1000) from the base image; the app files stay owned by root.
USER node
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "node", "/app/dist/server.js"]
