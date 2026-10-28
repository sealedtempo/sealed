# syntax=docker/dockerfile:1.7
# LiteLLM for the inference relay: upstream LiteLLM proxy v1.106.5 (MIT core) with the
# proprietary enterprise code deleted, flattened with FROM scratch so no layer carries it,
# plus the relay's static model config. Build context: this directory. Platform: linux/amd64.

FROM --platform=linux/amd64 ghcr.io/berriai/litellm-database:v1.106.5@sha256:0d10536ce596ef74bf5bbd3244310bb11c2cadd8f92d2f22d587cc0b9fc16e01 AS upstream
USER root
RUN set -eux; \
    SP=/app/.venv/lib/python3.13/site-packages; \
    test -d "$SP/litellm"; \
    rm -rf /app/enterprise "$SP/litellm_enterprise" "$SP"/litellm_enterprise-*.dist-info; \
    test ! -e /app/enterprise; \
    test -z "$(find / -xdev \( -name 'litellm_enterprise*' -o -path '*/enterprise/enterprise_hooks*' \) -print -quit)"; \
    /app/.venv/bin/python -I -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('litellm_enterprise') is None else 1)"
COPY config.yaml /etc/litellm/config.yaml
RUN set -eux; \
    export LITELLM_LOCAL_MODEL_COST_MAP=True HF_HUB_OFFLINE=1; \
    /app/.venv/bin/python -I -c "import litellm.proxy.proxy_server"; \
    /app/.venv/bin/python -I -c "import sys, yaml; c = yaml.safe_load(open('/etc/litellm/config.yaml')); assert all(m['litellm_params']['api_base'].startswith('http://inference-relay-') for m in c['model_list'])"; \
    rm -rf /root/.cache

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
    LITELLM_LOG=ERROR
LABEL org.opencontainers.image.source="https://github.com/BerriAI/litellm" \
      org.opencontainers.image.version="1.106.5" \
      org.opencontainers.image.revision="2569eb88694ce148dea5f324f240f79d256af8ae" \
      org.opencontainers.image.licenses="MIT" \
      sealed.base.digest="ghcr.io/berriai/litellm-database@sha256:0d10536ce596ef74bf5bbd3244310bb11c2cadd8f92d2f22d587cc0b9fc16e01"
WORKDIR /app
EXPOSE 4000/tcp
ENTRYPOINT ["docker/prod_entrypoint.sh"]
CMD ["--port", "4000", "--config", "/etc/litellm/config.yaml"]
