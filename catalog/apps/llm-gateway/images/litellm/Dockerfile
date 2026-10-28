# syntax=docker/dockerfile:1.7
# Sealed LiteLLM: upstream LiteLLM proxy v1.106.5 (MIT core) with the proprietary
# enterprise code deleted, flattened with FROM scratch so no layer carries it.
# Build context: this directory. Target platform: linux/amd64.

FROM --platform=linux/amd64 ghcr.io/berriai/litellm-database:v1.106.5@sha256:0d10536ce596ef74bf5bbd3244310bb11c2cadd8f92d2f22d587cc0b9fc16e01 AS upstream
USER root

# Remove both copies of the enterprise code (source dir and the litellm_enterprise
# wheel), then fail the build if anything enterprise is still present or importable.
RUN --network=none set -eux; \
    SP=/app/.venv/lib/python3.13/site-packages; \
    test -d "$SP/litellm"; \
    rm -rf /app/enterprise "$SP/litellm_enterprise" "$SP"/litellm_enterprise-*.dist-info; \
    test ! -e /app/enterprise; \
    test -z "$(find / -xdev \( -name 'litellm_enterprise*' -o -path '*/enterprise/enterprise_hooks*' \) -print -quit)"; \
    /app/.venv/bin/python -I -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('litellm_enterprise') is None else 1)"; \
    cd /app && /app/.venv/bin/python -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('enterprise') is None else 1)"

COPY config.yaml providers.yaml app_keys.yaml sealed_usage.py sealed_entrypoint.py sealed_keys.py /etc/litellm/

# Build-time checks against the real LiteLLM, with no network (--network=none), so any
# outbound call at import time fails the build: the proxy still imports without the
# enterprise package, the callback is a CustomLogger instance, the entrypoint renders a
# config with throwaway secrets, and the keys job (which runs as uid 65534) can read its
# config. Nothing from this step is kept.
RUN --network=none set -eux; \
    export LITELLM_LOCAL_MODEL_COST_MAP=True LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS=True \
           LITELLM_LOCAL_AUTOROUTER_PRESETS=True LITELLM_LOCAL_POLICY_TEMPLATES=True LITELLM_LOCAL_BLOG_POSTS=True \
           HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 CHECKPOINT_DISABLE=1 PRISMA_OFFLINE_MODE=true; \
    /app/.venv/bin/python -I -c "import litellm.proxy.proxy_server"; \
    /app/.venv/bin/python -I -c "import sys; sys.path.insert(0, '/etc/litellm'); import sealed_usage; from litellm.integrations.custom_logger import CustomLogger; assert isinstance(sealed_usage.usage_logger, CustomLogger)"; \
    d="$(mktemp -d)"; mkdir -p "$d/secrets"; \
    printf 'sk-%s' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$d/secrets/LITELLM_MASTER_KEY"; \
    printf 'sk-%s' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$d/secrets/LITELLM_SALT_KEY"; \
    printf 'build-check' > "$d/secrets/POSTGRES_PASSWORD"; \
    SEALED_SECRETS_DIR="$d/secrets" SEALED_LITELLM_RENDER_DIR="$d/out" \
      /app/.venv/bin/python -I /etc/litellm/sealed_entrypoint.py --render-only --port 4000; \
    /app/.venv/bin/python -I -c "import sys, yaml; c = yaml.safe_load(open(sys.argv[1])); assert c['litellm_settings']['callbacks'] == ['sealed_usage.usage_logger']; assert c['router_settings']['fallbacks'] == [{'relay/default': ['local/qwen3-4b']}]" "$d/out/config.yaml"; \
    /app/.venv/bin/python -I -c "import os, subprocess, sys; os.setgroups([]); os.setgid(65534); os.setuid(65534); sys.exit(subprocess.call(['/app/.venv/bin/python', '-I', '/etc/litellm/sealed_keys.py', '--check-config']))"; \
    rm -rf "$d" /etc/litellm/__pycache__ /root/.cache

FROM scratch
COPY --from=upstream / /
ENV PATH=/app/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    LITELLM_RELEASE_TAG=v1.106.5 \
    PRISMA_BINARY_CACHE_DIR=/opt/prisma/binaries \
    PRISMA_CLI_PATH=/opt/prisma/binaries/node_modules/.bin/prisma \
    PRISMA_CLI_QUERY_ENGINE_TYPE=binary \
    PRISMA_OFFLINE_MODE=true \
    CHECKPOINT_DISABLE=1 \
    LITELLM_MODE=PRODUCTION \
    LITELLM_LOCAL_MODEL_COST_MAP=True \
    LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS=True \
    LITELLM_LOCAL_AUTOROUTER_PRESETS=True \
    LITELLM_LOCAL_POLICY_TEMPLATES=True \
    LITELLM_LOCAL_BLOG_POSTS=True \
    LITELLM_OFFLINE_MODE=true \
    LITELLM_DISABLE_LATEST_RELEASE_CHECK=true \
    HF_HUB_OFFLINE=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    LITELLM_DONT_SHOW_FEEDBACK_BOX=true \
    DISABLE_ADMIN_UI=True \
    NO_DOCS=True \
    NO_REDOC=True \
    STORE_MODEL_IN_DB=False \
    LITELLM_LOG=ERROR
LABEL org.opencontainers.image.source="https://github.com/BerriAI/litellm" \
      org.opencontainers.image.version="1.106.5" \
      org.opencontainers.image.revision="2569eb88694ce148dea5f324f240f79d256af8ae" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="LiteLLM proxy MIT core for Sealed; enterprise/ and litellm_enterprise removed" \
      sealed.base.digest="ghcr.io/berriai/litellm-database@sha256:0d10536ce596ef74bf5bbd3244310bb11c2cadd8f92d2f22d587cc0b9fc16e01"
WORKDIR /app
EXPOSE 4000/tcp
ENTRYPOINT ["/app/.venv/bin/python", "-I", "/etc/litellm/sealed_entrypoint.py"]
CMD ["--port", "4000"]
