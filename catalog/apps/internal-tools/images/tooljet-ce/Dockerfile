# Sealed internal-tools image: ToolJet CE v3.20.251-lts without the bundled Redis server and
# without Oracle Instant Client, flattened so that neither exists in any layer (decision D-018a).
#
# Upstream ships redis-server 8.10.3 from packages.redis.io (RSALv2/SSPLv1/AGPLv3; D-020 uses
# Valkey instead) with its modules in /usr/lib/redis/modules (RediSearch, RedisJSON, RedisBloom,
# RedisTimeSeries), and Oracle Instant Client 11.2 and 21.10 (Oracle license, not on the rule 9
# list). ToolJet's Oracle data source keeps working in thin mode, which needs no client library.
# Upstream also bundles @sap/hana-client (the SAP HANA client, under a proprietary SAP developer
# license, not on the rule 9 list; D-021): remove it. It is only used by ToolJet's optional SAP HANA
# data source, so dropping it disables that one connector and nothing else.
#
# ToolJet's enterprise edition is the private git submodules server/ee and frontend/ee. The CE
# image (docker/ce-production.Dockerfile at the tag) copies only build output (server/dist,
# frontend/build, plugins/dist and node_modules), so no ee directory reaches it; the build fails
# if any file or directory named ee exists under /app outside node_modules, where "ee" is the
# Ewe locale code of third-party data (license audit F7, manifest license_exclusions "/app/**/ee/").
# Built by the runtime image workflow (linux/amd64); its digest is then pinned in manifest.yaml.

FROM docker.io/tooljet/tooljet-ce@sha256:46d1c621efe69c490884cf17d60fbf5c58a9ec3dc57e37432cfd426a11593f47 AS upstream

USER root
# The RUN ends by removing the logs and caches apt, dpkg and ldconfig write with the build time in them, so
# a no-cache rebuild gives the same digest (D-028).
RUN set -eux; \
    test "$(cat /app/server/.version)" = "3.20.251-lts"; \
    test "$(id -u appuser)" = "1000"; \
    test "$(id -g appuser)" = "1000"; \
    apt-get purge -y --auto-remove redis-server redis-tools; \
    rm -rf /etc/apt/sources.list.d/redis.list /usr/share/keyrings/redis-archive-keyring.gpg \
           /var/lib/redis /var/log/redis /etc/redis /usr/lib/redis /app/redis.conf; \
    rm -rf /opt/oracle /etc/ld.so.conf.d/oracle-instantclient.conf; \
    rm -rf /app/plugins/node_modules/@sap/hana-client; \
    ldconfig; \
    rm -f /app/server/entrypoint.sh; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/* /root/.npm; \
    # apt, dpkg and ldconfig record the build time (or inode times) in these files, which gave every
    # build a new digest, so the workflow's no-cache rebuild check failed (images-preflight).
    rm -f /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log /var/log/alternatives.log /var/cache/ldconfig/aux-cache; \
    if find / -xdev \( -name 'redis-server' -o -name 'redis-check-*' -o -name 'redis-benchmark' \
         -o -path '/usr/lib/redis*' -o -path '/etc/redis*' -o \( -name '*.so' -path '*redis*' \) \
         -o -name 'libclntsh*' -o -name 'libnnz*' -o -name 'libociei*' -o -name 'libociicus*' -o -name 'libocci*' \
         -o -path '*/node_modules/@sap/hana-client*' \) -print | grep -q .; then \
      echo "forbidden binaries left in the image" >&2; exit 1; \
    fi; \
    if find /app -xdev -path '*/node_modules' -prune -o -name ee -print | grep -q .; then \
      echo "ToolJet enterprise (ee) paths in the image" >&2; exit 1; \
    fi; \
    rm -rf /var/log/dpkg.log /var/log/apt /var/log/alternatives.log /var/cache/ldconfig/aux-cache /var/cache/debconf/*-old /var/lib/dpkg/*-old

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
