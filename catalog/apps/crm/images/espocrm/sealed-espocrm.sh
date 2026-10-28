#!/bin/sh
# Entrypoint of the Sealed crm image (EspoCRM 10.0.11 on Debian packages, decision D-049a).
#
#   sealed-espocrm server          Apache with mod_php on port 8080, the crm route. Once EspoCRM
#                                  is installed it clears the cache and runs `migrate` first,
#                                  so a new image upgrades the database before it serves.
#   sealed-espocrm daemon          EspoCRM's job daemon (php daemon.php) once installed.
#   sealed-espocrm bootstrap CMD   runs CMD (the crm-bootstrap job) as www-data.
#   sealed-espocrm write-config D  writes the two override files into D and exits (build check).
#
# Started as root, it gives the data volumes to www-data (uid 33) on first use, then runs itself
# again as www-data with no capabilities and no_new_privs. Every mode then writes
# data/config-override.php and data/config-internal-override.php: EspoCRM merges them over
# data/config.php and data/config-internal.php, so the settings Sealed fixes (public URL,
# database, no update checks or admin-panel iframe, no extension uploads or upgrades from the
# UI) always win over what the admin panel stores. The database password lives only in that
# internal override file (mode 0600, on the encrypted data disk) and in this process's env.
set -eu

ESPO_DIR=${SEALED_ESPO_DIR:-/var/www/html}
SKEL_DIR=${SEALED_ESPO_SKEL:-/opt/espocrm/skel}
APACHE_CONF=${SEALED_APACHE_CONF:-/etc/apache2/sealed.conf}
WWW_UID=33
WWW_GID=33
VOLUME_DIRS="data custom client/custom"

die() {
  echo "sealed-espocrm: $*" >&2
  exit 1
}

mode=${1:-}
[ $# -gt 0 ] && shift
case $mode in
  server | daemon | bootstrap | write-config) ;;
  *) die "usage: sealed-espocrm server|daemon|bootstrap <cmd...>|write-config <dir>" ;;
esac

# Checked with shell builtins only, so the values never reach another process's argv.
check_env() {
  url=${SEALED_PUBLIC_URL_CRM:-}
  [ -n "$url" ] || die "SEALED_PUBLIC_URL_CRM is not set (the composer sets it on every crm service)"
  case $url in
    https://*) ;;
    *) die "SEALED_PUBLIC_URL_CRM must start with https://" ;;
  esac
  host=${url#https://}
  case $host in
    '' | *[!A-Za-z0-9.:-]*) die "SEALED_PUBLIC_URL_CRM must be https://<host>[:port] with no path or trailing slash" ;;
  esac
  pw=${PG_DATABASE_PASSWORD:-}
  case $pw in
    '' | *[!A-Za-z0-9]*) die "PG_DATABASE_PASSWORD must be set and use only [A-Za-z0-9]" ;;
  esac
  [ "${#pw}" -ge 16 ] && [ "${#pw}" -le 128 ] || die "PG_DATABASE_PASSWORD must be 16 to 128 characters"
  check_switches
}

# The manifest's telemetry_off_env (added by the composer to every crm service). The values
# written into config-override.php are fixed below; these variables must be present with exactly
# those values, so the measured manifest and the image can never disagree silently.
SWITCHES="ESPOCRM_CONFIG_USE_WEB_SOCKET=false
ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS=false
ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS_NEW_VERSION=false
ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS_NEW_EXTENSION_VERSION=false
ESPOCRM_CONFIG_ADMIN_PANEL_IFRAME_DISABLED=true
ESPOCRM_CONFIG_ADMIN_EXTENSION_UPLOAD=false
ESPOCRM_CONFIG_ADMIN_UPGRADE_DISABLED=true"

check_switches() {
  for pair in $SWITCHES; do
    name=${pair%%=*}
    want=${pair#*=}
    eval "got=\${$name-unset}"
    [ "$got" = "$want" ] || die "$name must be $want (telemetry_off_env), got $got"
  done
}

# Writes <file> through a temporary file in the same directory, so readers never see half of it.
write_file() {
  target=$1
  tmp="$target.tmp.$$"
  cat > "$tmp"
  mv -f "$tmp" "$target"
}

write_config() {
  dir=$1
  old_umask=$(umask)
  umask 077
  write_file "$dir/config-override.php" <<EOF
<?php
// Written by sealed-espocrm on every start (catalog/apps/crm/images/espocrm). EspoCRM merges
// these values over data/config.php, so changing them in the admin panel has no effect.
return [
    'siteUrl' => '$url',
    'useWebSocket' => false,
    'adminNotifications' => false,
    'adminNotificationsNewVersion' => false,
    'adminNotificationsNewExtensionVersion' => false,
    'adminNotificationsCronIsNotConfigured' => false,
    'adminPanelIframeDisabled' => true,
    'adminPanelIframeUrl' => 'about:blank',
    'adminExtensionUpload' => false,
    'adminUpgrade' => false,
    'adminUpgradeDisabled' => true,
    'phpExecutablePath' => '/usr/bin/php',
];
EOF
  write_file "$dir/config-internal-override.php" <<EOF
<?php
// Written by sealed-espocrm on every start from PG_DATABASE_PASSWORD (a crm secret).
return [
    'database' => [
        'platform' => 'Postgresql',
        'host' => 'crm-db',
        'port' => 5432,
        'dbname' => 'espocrm',
        'user' => 'espocrm',
        'password' => '$pw',
    ],
];
EOF
  umask "$old_umask"
}

# Copies the files EspoCRM ships in data/, custom/ and client/custom/ into the volumes when they
# are missing (first start). Never overwrites.
seed_volumes() {
  [ -d "$SKEL_DIR" ] || return 0
  (cd "$SKEL_DIR" && find . -type d) | while IFS= read -r d; do
    mkdir -p "$ESPO_DIR/$d"
  done
  (cd "$SKEL_DIR" && find . -type f) | while IFS= read -r f; do
    [ -e "$ESPO_DIR/$f" ] || cp -p "$SKEL_DIR/$f" "$ESPO_DIR/$f"
  done
}

php_command() {
  (cd "$ESPO_DIR" && php bin/command "$@")
}

installed() {
  [ "$(php_command config:get isInstalled 2>/dev/null || true)" = "true" ]
}

if [ "$mode" = write-config ]; then
  [ $# -eq 1 ] || die "usage: sealed-espocrm write-config <dir>"
  check_env
  write_config "$1"
  exit 0
fi

check_env

if [ "$(id -u)" = 0 ]; then
  owned_dirs=""
  for d in $VOLUME_DIRS; do
    owned_dirs="$owned_dirs $ESPO_DIR/$d"
  done
  [ -n "${STATE_DIR:-}" ] && owned_dirs="$owned_dirs $STATE_DIR"
  for d in $owned_dirs; do
    mkdir -p "$d"
    if [ "$(stat -c %u:%g "$d")" != "$WWW_UID:$WWW_GID" ]; then
      chown -R "$WWW_UID:$WWW_GID" "$d"
    fi
  done
  exec setpriv --reuid="$WWW_UID" --regid="$WWW_GID" --clear-groups --inh-caps=-all \
    --bounding-set=-all --no-new-privs -- "$0" "$mode" "$@"
fi

[ "$(id -u)" = "$WWW_UID" ] || die "must run as root or as www-data (uid $WWW_UID)"

seed_volumes
write_config "$ESPO_DIR/data"

case $mode in
  server)
    if installed; then
      php_command clear-cache > /dev/null
      php_command migrate || die "migrate failed: the data may be incompatible with this image. Check data/logs, then restart crm-server"
    fi
    mkdir -p /tmp/apache2
    exec apache2 -f "$APACHE_CONF" -DFOREGROUND
    ;;
  daemon)
    until installed; do
      echo "sealed-espocrm: waiting for crm-bootstrap to install EspoCRM" >&2
      sleep 10
    done
    cd "$ESPO_DIR"
    exec php daemon.php
    ;;
  bootstrap)
    [ $# -gt 0 ] || die "bootstrap needs a command"
    cd "$ESPO_DIR"
    exec "$@"
    ;;
esac
