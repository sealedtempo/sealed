#!/bin/bash
# ToolJet CE entrypoint for Sealed. Same steps as upstream docker/ce-entrypoint.sh at
# v3.20.251-lts, minus starting the bundled Redis (Valkey runs as its own service) and minus
# reading a .env file (all configuration comes from the measured compose environment).
#   1. wait for PostgreSQL, then create the databases and run the migrations;
#   2. exec the command (default: node dist/src/main) from /app/server.
set -euo pipefail

: "${PG_HOST:?PG_HOST is required}"
cd /app
./server/scripts/wait-for-it.sh "${PG_HOST}:${PG_PORT:-5432}" --strict --timeout=300 -- npm run db:setup:prod

cd /app/server
exec "$@"
