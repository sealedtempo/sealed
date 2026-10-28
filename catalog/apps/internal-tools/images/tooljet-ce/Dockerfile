# Sealed internal-tools image: ToolJet CE v3.20.251-lts without the bundled Redis server and
# without Oracle Instant Client, flattened so that neither exists in any layer (decision D-018a).
#
# Upstream ships redis-server 8.10.3 from packages.redis.io (RSALv2/SSPLv1/AGPLv3; D-020 uses
# Valkey instead) and Oracle Instant Client 11.2 and 21.10 (Oracle license, not on the rule 9
# list). ToolJet's Oracle data source keeps working in thin mode, which needs no client library.
# Built by the runtime image workflow (linux/amd64); its digest is then pinned in manifest.yaml.

FROM docker.io/tooljet/tooljet-ce@sha256:46d1c621efe69c490884cf17d60fbf5c58a9ec3dc57e37432cfd426a11593f47 AS upstream

USER root
RUN set -eux; \
    test "$(cat /app/server/.version)" = "3.20.251-lts"; \
    test "$(id -u appuser)" = "1000"; \
    test "$(id -g appuser)" = "1000"; \
    apt-get purge -y --auto-remove redis-server redis-tools; \
    rm -rf /etc/apt/sources.list.d/redis.list /usr/share/keyrings/redis-archive-keyring.gpg \
           /var/lib/redis /var/log/redis /etc/redis /app/redis.conf; \
    rm -rf /opt/oracle /etc/ld.so.conf.d/oracle-instantclient.conf; \
    ldconfig; \
    rm -f /app/server/entrypoint.sh; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/* /root/.npm; \
    if find / -xdev \( -name 'redis-server' -o -name 'redis-check-*' -o -name 'redis-benchmark' \
         -o -name 'libclntsh*' -o -name 'libnnz*' -o -name 'libociei*' -o -name 'libociicus*' -o -name 'libocci*' \) -print | grep -q .; then \
      echo "forbidden binaries left in the image" >&2; exit 1; \
    fi

COPY --chmod=0755 sealed-entrypoint.sh /app/server/sealed-entrypoint.sh

FROM scratch
COPY --from=upstream / /

ENV PATH=/usr/local/lib/nodejs/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    ICU_TIMEZONE_FILES_DIR=/usr/local/share/icu-tz \
    NODE_ENV=production \
    NODE_OPTIONS=--max-old-space-size=4096 \
    npm_config_cache=/home/appuser/.npm \
    HOME=/home/appuser

LABEL org.opencontainers.image.title="sealed internal-tools (ToolJet CE)" \
      org.opencontainers.image.version="3.20.251-lts" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/ToolJet/ToolJet/tree/v3.20.251-lts" \
      org.opencontainers.image.base.name="docker.io/tooljet/tooljet-ce:v3.20.251-lts" \
      org.opencontainers.image.base.digest="sha256:46d1c621efe69c490884cf17d60fbf5c58a9ec3dc57e37432cfd426a11593f47"

USER appuser
WORKDIR /app
ENTRYPOINT ["/app/server/sealed-entrypoint.sh"]
CMD ["node", "dist/src/main"]
