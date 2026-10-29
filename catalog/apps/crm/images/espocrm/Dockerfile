# Sealed crm image: EspoCRM 10.0.11 (AGPL-3.0-or-later) on Debian trixie packages (decision D-049a).
#
# Built by the runtime image workflow for linux/amd64; the digest is then pinned in manifest.yaml
# (D-028). Build context: this directory.
#
# What runs comes from two sources only:
#   - Debian trixie packages from a fixed snapshot.debian.org date (Apache httpd, PHP 8.4 with
#     mod_php, Node.js 20 for the crm-bootstrap job), so every OS package version is pinned and
#     counts as an OS package for the license policy (D-021, D-050);
#   - the EspoCRM release zip, checked against the sha256 that EspoCRM's own image publishes.
# EspoCRM's web installer is removed (the crm-bootstrap job installs with EspoCRM's CLI), and the
# build fails if any application PHP file lacks EspoCRM's AGPL header, if any Composer package is
# outside the license allowlist, or if a file carries an "@license Enterprise" marker.
#
# Apache runs as www-data on port 8080 and drops every Authorization header (apache-sealed.conf).

ARG DEBIAN_SNAPSHOT=20261027T000000Z

# ---------------------------------------------------------------------------------------------
# fetch: download, verify and prune the EspoCRM release
# ---------------------------------------------------------------------------------------------
FROM docker.io/library/debian:trixie-20261020-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS fetch
ARG DEBIAN_SNAPSHOT
ARG ESPOCRM_VERSION=10.0.11
# From github.com/espocrm/espocrm-docker tag 10.0.11 (commit a2f3e9cba6edb596afdafca2b9ac6d639fd29c5c).
ARG ESPOCRM_SHA256=cdd04f7efa52a59025ef824c75b06e0a84cf986724a8c5bc4b56fcd2ce8e0ab1

RUN set -eux; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} trixie main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} trixie-updates main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} trixie-security main" \
      > /etc/apt/sources.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl jq unzip; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/EspoCRM.zip \
      "https://www.espocrm.com/downloads/EspoCRM-${ESPOCRM_VERSION}.zip"; \
    echo "${ESPOCRM_SHA256}  /tmp/EspoCRM.zip" | sha256sum -c -; \
    mkdir /unpack; \
    unzip -q /tmp/EspoCRM.zip -d /unpack; \
    mv "/unpack/EspoCRM-${ESPOCRM_VERSION}" /espocrm; \
    rm -rf /unpack /tmp/EspoCRM.zip; \
    grep -q "'version' => '${ESPOCRM_VERSION}'" /espocrm/application/Espo/Resources/defaults/config.php; \
    # The web installer: never shipped, the bootstrap job installs with bin/command.
    rm -rf /espocrm/install /espocrm/public/install; \
    # Skeletons of the three writable directories, copied into the volumes on first start.
    mkdir -p /skel/client; \
    mv /espocrm/data /skel/data; \
    mv /espocrm/custom /skel/custom; \
    mv /espocrm/client/custom /skel/client/custom; \
    mkdir -p /espocrm/data /espocrm/custom /espocrm/client/custom

# License gates. EspoCRM ships one module (Crm) and no paid extensions; these checks fail the
# build if a future release changes that.
RUN set -eux; \
    test "$(ls /espocrm/application/Espo/Modules)" = "Crm"; \
    test -z "$(find /espocrm/application -name '*.php' ! -exec grep -q 'GNU Affero General Public License' {} \; -print)"; \
    test -z "$(grep -rIl --exclude-dir=node_modules '@license Enterprise' /espocrm /skel || true)"; \
    jq -e '.packages | length > 100' /espocrm/vendor/composer/installed.json > /dev/null; \
    bad="$(jq -r '.packages[] | select(((.license // []) | any(. as $l | ["MIT","BSD-2-Clause","BSD-3-Clause","Apache-2.0","ISC","MPL-2.0","LGPL-2.1","LGPL-2.1-only","LGPL-2.1-or-later","LGPL-3.0","LGPL-3.0-only","LGPL-3.0-or-later","GPL-3.0-or-later","AGPL-3.0-or-later"] | index($l))) | not) | "\(.name) \(.license)"' /espocrm/vendor/composer/installed.json)"; \
    if [ -n "$bad" ]; then echo "Composer packages outside the license allowlist: $bad" >&2; exit 1; fi; \
    chown -R root:root /espocrm /skel; \
    find /espocrm /skel -type d -exec chmod 0755 {} +; \
    find /espocrm /skel -type f -exec chmod 0644 {} +; \
    chmod 0755 /espocrm/bin/command

# ---------------------------------------------------------------------------------------------
# runtime
# ---------------------------------------------------------------------------------------------
FROM docker.io/library/debian:trixie-20261020-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
ARG DEBIAN_SNAPSHOT
ARG ESPOCRM_VERSION=10.0.11

RUN set -eux; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} trixie main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} trixie-updates main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} trixie-security main" \
      > /etc/apt/sources.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      apache2 libapache2-mod-php8.4 media-types \
      php8.4-cli php8.4-pgsql php8.4-gd php8.4-zip php8.4-xml php8.4-mbstring php8.4-curl \
      php8.4-intl php8.4-bcmath php8.4-opcache \
      nodejs ca-certificates; \
    # apt, dpkg and ldconfig record the build time (or inode times) in these files, which gave every
    # build a new digest, so the workflow's no-cache rebuild check failed (images-preflight).
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt /var/log/dpkg.log /var/log/alternatives.log \
           /var/cache/ldconfig/aux-cache; \
    # Debian's default site, docroot and logs are not used (apache-sealed.conf).
    rm -rf /var/www/html /etc/apache2/sites-enabled/* /var/log/apache2/*; \
    test "$(id -u www-data):$(id -g www-data)" = "33:33"

COPY --from=fetch /espocrm /var/www/html
COPY --from=fetch /skel /opt/espocrm/skel
COPY apache-sealed.conf /etc/apache2/sealed.conf
COPY php-sealed.ini /etc/php/8.4/apache2/conf.d/90-sealed.ini
COPY php-sealed.ini /etc/php/8.4/cli/conf.d/90-sealed.ini
COPY --chmod=0755 sealed-espocrm.sh /usr/local/bin/sealed-espocrm

# Build-time checks of the runtime: PHP extensions EspoCRM needs, Node for the bootstrap, the
# Apache configuration, and the override files sealed-espocrm writes (syntax and values).
RUN set -eux; \
    for ext in pdo_pgsql gd zip mbstring xml xmlwriter curl intl bcmath exif iconv openssl json fileinfo 'Zend OPcache'; do \
      php -m | grep -qix "$ext" || { echo "missing PHP extension $ext" >&2; exit 1; }; \
    done; \
    node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)'; \
    mkdir -p /tmp/apache2; \
    apache2 -f /etc/apache2/sealed.conf -t; \
    mkdir /tmp/selftest; \
    env SEALED_PUBLIC_URL_CRM=https://crm.selftest.example PG_DATABASE_PASSWORD=0123456789abcdef0123456789abcdef \
      ESPOCRM_CONFIG_USE_WEB_SOCKET=false ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS=false \
      ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS_NEW_VERSION=false ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS_NEW_EXTENSION_VERSION=false \
      ESPOCRM_CONFIG_ADMIN_PANEL_IFRAME_DISABLED=true ESPOCRM_CONFIG_ADMIN_EXTENSION_UPLOAD=false \
      ESPOCRM_CONFIG_ADMIN_UPGRADE_DISABLED=true \
      /usr/local/bin/sealed-espocrm write-config /tmp/selftest; \
    php -l /tmp/selftest/config-override.php; \
    php -l /tmp/selftest/config-internal-override.php; \
    php -r '$c = include "/tmp/selftest/config-override.php"; $i = include "/tmp/selftest/config-internal-override.php"; exit($c["siteUrl"] === "https://crm.selftest.example" && $c["adminNotifications"] === false && $c["adminExtensionUpload"] === false && $i["database"]["platform"] === "Postgresql" && $i["database"]["password"] === "0123456789abcdef0123456789abcdef" ? 0 : 1);'; \
    test "$(stat -c %a /tmp/selftest/config-internal-override.php)" = "600"; \
    rm -rf /tmp/selftest /tmp/apache2; \
    test ! -e /var/www/html/install; \
    test ! -e /var/www/html/public/install; \
    chown 33:33 /var/www/html/data /var/www/html/custom /var/www/html/client/custom

LABEL org.opencontainers.image.title="sealed crm (EspoCRM)" \
      org.opencontainers.image.version="10.0.11" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/espocrm/espocrm/tree/10.0.11" \
      org.opencontainers.image.base.name="docker.io/library/debian:trixie-20261020-slim" \
      org.opencontainers.image.base.digest="sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad"

WORKDIR /var/www/html
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sealed-espocrm"]
CMD ["server"]
