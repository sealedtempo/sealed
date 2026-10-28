# syntax=docker/dockerfile:1.7
# Sealed OpenCode: upstream OpenCode 1.19.5 (MIT) plus bash, git and python3 for the agent's
# shell, running as uid 10001. Fallback coding agent only (not in the default release).
# Build context: this directory. Target platform: linux/amd64.

FROM --platform=linux/amd64 ghcr.io/anomalyco/opencode:1.19.5@sha256:f4cfe16d91efbbfca01a51c44094fba4cf82e15c7fa17de5f11f9059699b1e6e

# apk versions are recorded in the image (and the SBOM) because Alpine packages are not
# version-pinned by apk add; the image digest pins the result.
RUN set -eux; \
    apk add --no-cache bash git python3; \
    addgroup -g 10001 opencode; \
    adduser -D -u 10001 -G opencode -h /home/opencode -s /bin/bash opencode; \
    mkdir -p /workspace/project; \
    chown -R 10001:10001 /workspace; \
    mkdir -p /usr/share/sealed; \
    apk info -v | sort > /usr/share/sealed/apk-versions.txt; \
    OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 opencode --version; \
    python3 -I -c "import pwd; assert pwd.getpwuid(10001).pw_dir == '/home/opencode'"; \
    test -z "$(find / -xdev -path '*@anthropic-ai/claude-agent-sdk*' -print -quit)"

USER 10001:10001
WORKDIR /workspace/project
ENV HOME=/home/opencode \
    BUN_RUNTIME_TRANSPILER_CACHE_PATH=0 \
    OPENCODE_DISABLE_AUTOUPDATE=1 \
    OPENCODE_DISABLE_MODELS_FETCH=1 \
    OPENCODE_DISABLE_LSP_DOWNLOAD=1 \
    OPENCODE_DISABLE_DEFAULT_PLUGINS=1 \
    OPENCODE_DISABLE_CLAUDE_CODE=1
LABEL org.opencontainers.image.source="https://github.com/anomalyco/opencode" \
      org.opencontainers.image.version="1.19.5" \
      org.opencontainers.image.revision="810c0eba1a7348036f8bdf61e6632d0c36c6876c" \
      org.opencontainers.image.licenses="MIT" \
      sealed.base.digest="ghcr.io/anomalyco/opencode@sha256:f4cfe16d91efbbfca01a51c44094fba4cf82e15c7fa17de5f11f9059699b1e6e"
EXPOSE 4096
ENTRYPOINT ["opencode"]
CMD ["serve", "--hostname", "0.0.0.0", "--port", "4096"]
