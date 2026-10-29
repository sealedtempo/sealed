# scraper-runner with Playwright Firefox: the image the catalog release ships.
#
# Build from the repository root (the build context needs tsconfig.base.json):
#   docker build -f catalog/apps/scraper/images/scraper-runner-playwright/Dockerfile -t scraper-runner-playwright .
# Dockerfile.dockerignore next to this file limits the context to the runner sources.
#
# Base: mcr.microsoft.com/playwright:v1.62.1-noble (Ubuntu 24.04, Node 24), index digest below.
#   linux/amd64 child: sha256:c091b21d9fae78c76e85cd4356431e9b018402f172a214fc7d7a5e9a7e29d8ac
# The image tag must match the playwright npm version in runner/package.json (1.62.1), or
# Playwright cannot find /ms-playwright/firefox-<revision>.
#
# Only Firefox (MPL-2.0) is kept. The base also ships Chromium, which on Linux x64 is Google's
# Chrome for Testing with unclear license terms (D-022), plus WebKit and ffmpeg. Deleting them in
# a later layer would still ship them in the base layers, so the final stage copies the cleaned
# filesystem into a single fresh layer.

FROM mcr.microsoft.com/playwright:v1.62.1-noble@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e AS build
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 CI=1
RUN npm install --global --ignore-scripts pnpm@10.33.2
WORKDIR /src
COPY tsconfig.base.json ./
COPY catalog/apps/scraper/runner/package.json catalog/apps/scraper/runner/pnpm-lock.yaml catalog/apps/scraper/runner/
WORKDIR /src/catalog/apps/scraper/runner
RUN pnpm install --frozen-lockfile --ignore-workspace
COPY catalog/apps/scraper/runner/tsconfig.json catalog/apps/scraper/runner/tsconfig.build.json ./
COPY catalog/apps/scraper/runner/src ./src
RUN pnpm run build
# pnpm writes the install time into node_modules/.modules.yaml (prunedAt) and
# .pnpm-workspace-state-v1.json (lastValidatedTimestamp), so every build had a new digest and the
# workflow's no-cache rebuild check failed (images-preflight). Neither file is read at run time.
RUN mkdir /app \
 && cp package.json pnpm-lock.yaml /app/ \
 && cd /app \
 && pnpm install --frozen-lockfile --ignore-workspace --prod \
 && rm -f /app/node_modules/.modules.yaml /app/node_modules/.pnpm-workspace-state-v1.json \
 && cp -r /src/catalog/apps/scraper/runner/dist /app/dist

FROM mcr.microsoft.com/playwright:v1.62.1-noble@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e AS rootfs
# apt, dpkg and ldconfig record the build time (or inode times) in their logs and in ldconfig's
# aux-cache; shipped in the image, those files gave every build a new digest, so the workflow's
# no-cache rebuild check failed (images-preflight). They are removed with the package lists.
RUN rm -rf /ms-playwright/chromium-* /ms-playwright/chromium_headless_shell-* /ms-playwright/webkit-* /ms-playwright/ffmpeg-* \
 && ls -d /ms-playwright/firefox-* \
 && chmod -R go-w /ms-playwright \
 && apt-get update \
 && apt-get install -y --no-install-recommends tini=0.19.0-1 \
 && apt-get purge -y git openssh-client \
 && npm uninstall --global yarn \
 && rm -rf /var/lib/apt/lists/* /root/.npm /tmp/* \
 && rm -f /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log /var/log/alternatives.log /var/cache/ldconfig/aux-cache
COPY --from=build /app /app

FROM scratch
COPY --from=rootfs / /
# The scratch stage starts with no config, so the base image's environment is restated.
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    NODE_ENV=production \
    PORT=8080 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    CRAWLEE_PERSIST_STORAGE=false \
    CRAWLEE_STORAGE_DIR=/tmp/crawlee \
    CRAWLEE_HEADLESS=1
WORKDIR /app
# Non-root (pwuser from the base image). Firefox keeps its default content sandbox: nothing here
# sets MOZ_DISABLE_*_SANDBOX, and the runner strips those variables at start.
USER pwuser
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "node", "/app/dist/server.js"]
