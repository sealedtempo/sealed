# internal-tools: ToolJet Community Edition

[ToolJet](https://github.com/ToolJet/ToolJet) CE v3.20.251-lts, a low-code builder for internal
apps (forms, tables, admin panels) over databases and APIs, with its own table store (ToolJet
Database, served by PostgREST). Route `tools`, behind the Sealed gate. Metered in app hours from
heartbeats.

## Why ToolJet and not Appsmith (decision D-018a)

D-018 allowed Appsmith CE only if FerretDB 2.x covers what Appsmith needs from MongoDB. It does not:

- Appsmith CE v2.5.1 refuses to start on an external store that is not a replica set:
  `entrypoint.sh` runs `appsmithctl check-replica-set`, which opens a change stream on the `user`
  collection and exits 1 if that fails
  ([check_replica_set.ts](https://github.com/appsmithorg/appsmith/blob/v2.5.1/app/client/packages/rts/src/ctl/check_replica_set.ts)).
  The server also configures `ReactiveMongoTransactionManager` and wraps application import in
  `transactionalOperator::transactional`
  ([MongoConfig.java](https://github.com/appsmithorg/appsmith/blob/v2.5.1/app/server/appsmith-server/src/main/java/com/appsmith/server/configurations/MongoConfig.java)).
- FerretDB 2.7 (latest release, docs for the unreleased 2.8 say the same) lists `commitTransaction`
  and `abortTransaction` as not implemented ([compatibility](https://docs.ferretdb.io/migration/compatibility/),
  issues [#1547](https://github.com/FerretDB/FerretDB/issues/1547) and #1548), and change streams
  are an open issue blocked upstream in DocumentDB ([#175](https://github.com/FerretDB/FerretDB/issues/175)).
  Its flags have no replica set emulation for 2.x ([flags](https://docs.ferretdb.io/configuration/flags/)).
- Appsmith's own docs for an external store require MongoDB 5.0+ initialised as a replica set
  (`rs.initiate()`) and name no MongoDB-compatible alternative
  ([custom MongoDB](https://docs.appsmith.com/getting-started/setup/instance-configuration/custom-mongodb-redis)).
  The PostgreSQL metadata mode is not in the CE image.

So the fallback applies: a license-clean builder that runs on PostgreSQL. Evaluated on
2026-10-28:

| candidate | license (rule 9) | enterprise code in the shipped image | metadata store | maintained | telemetry controls | API to create an app | result |
|---|---|---|---|---|---|---|---|
| Appsmith CE 2.5.1 + FerretDB 2.7 | Apache-2.0 | none | needs a MongoDB replica set with transactions | yes | many switches plus a cloud-services sink | yes | does not start (above) |
| ToolJet CE 3.20.251-lts | AGPL-3.0 | none: enterprise code is in private submodules `server/ee`, `frontend/ee`; the CE server dist has no `ee` directory and its enterprise modules are stubs (checked in the image layer) | PostgreSQL 13+, PostgREST (MIT), a Redis-compatible queue | yes, LTS line, image built 2026-10-27 | `DISABLE_TOOLJET_TELEMETRY`, marketplace and trial URLs overridable | yes: `setup-super-admin`, `authenticate`, `POST /api/apps` | chosen |
| NocoBase | NocoBase License Agreement: Apache-2.0 plus terms that ban offering it as a low-code SaaS/PaaS and require keeping its branding; not OSI | commercial plugins | PostgreSQL | yes | n/a | yes | rejected, license |
| Budibase | GPL-3.0, but paid features live in `packages/pro` under BSL, and the bundled SQS server is licensed separately by its owner | yes (`packages/pro`) | CouchDB, MinIO, Redis | yes | n/a | yes | rejected, license and store |
| Lowcoder | AGPL-3.0 | none | MongoDB | yes | n/a | yes | rejected, same MongoDB problem |
| Baserow | MIT outside `premium/` and `enterprise/`, which have their own licenses | the premium and enterprise directories are part of the same repository and image | PostgreSQL | yes | n/a | yes | rejected, enterprise directories (and it is a database UI, not an app builder) |
| ILLA Builder | Apache-2.0 | none | PostgreSQL | no: last image August 2024 | n/a | yes | rejected, unmaintained |
| Saltcorn | MIT | none | PostgreSQL | yes, smaller project | none needed | partly (CLI and packs) | fallback if ToolJet regresses |

Two parts of the stock ToolJet CE image are not allowed and are removed by our derived image
(`images/tooljet-ce/Dockerfile`, flattened so they are in no layer):

- `redis-server` and `redis-tools` 8.10.3 from packages.redis.io (RSALv2/SSPLv1/AGPLv3; D-020
  replaces Redis with Valkey, which runs as its own service), including the Redis 8 modules in
  `/usr/lib/redis/modules` (RediSearch, RedisJSON, RedisBloom, RedisTimeSeries) and `/etc/redis`;
- Oracle Instant Client 11.2 and 21.10 under `/opt/oracle` (Oracle license). The Oracle data source
  still works in thin mode, which needs no client library; thick mode is unavailable.

The image's own entrypoint started the bundled Redis; `sealed-entrypoint.sh` does the same
database setup without it.

## Pins

| image | source | digest | license |
|---|---|---|---|
| tooljet | `build:images/tooljet-ce` from `docker.io/tooljet/tooljet-ce:v3.20.251-lts` `sha256:46d1c621efe69c490884cf17d60fbf5c58a9ec3dc57e37432cfd426a11593f47` | pending: `sha256:0000000000000000000000000000000000000000000000000000000000000000` until the runtime image workflow builds it | AGPL-3.0-only |
| postgrest | `docker.io/postgrest/postgrest:v12.2.12` | `sha256:5f4ce744539bbba786b4e24dbbd95bdb2a956dcf568c5374995a0ff4a68f5bd2` | MIT |
| postgres | `docker.io/library/postgres:16.15` | `sha256:1beaa3084eee2676f20a9cd9928f0bf2c5bf674f8e49f81017912183d377c61c` | PostgreSQL |
| valkey | `docker.io/valkey/valkey:9.0.7` | `sha256:7e1deda01b64ece3167d370ab5be3452d29734feec22cbcbc69b3a64f6859d6d` | BSD-3-Clause |

ToolJet's docs pin PostgREST 12.2; 12.2.12 is the last patch of that line. Catalog lint blocks a
release while the tooljet digest is all zeros (D-028). After the image is built, check it with:

```sh
crane export --platform linux/amd64 ghcr.io/sealed-dev/tooljet@<digest> - | tar -t \
  | node catalog/apps/internal-tools/tools/check-image-paths.mjs
```

which fails if any path from `license_exclusions` (the `ee` directories, `/opt/oracle/`, the Redis
binaries, `/usr/lib/redis/` and `/etc/redis/`) is present. The Dockerfile's own `find` fails the
build on the same files, and on any `.so` with `redis` in its path.

## Services

| service | what it runs |
|---|---|
| `internal-tools-server` | ToolJet API, web UI (`SERVE_CLIENT=true`) and workflow workers (`WORKER=true`). Runs migrations at start, on the setup port 3001 until `internal-tools-bootstrap/done.json` exists, then on port 3000, the route port. Primary service and route target. |
| `internal-tools-postgrest` | PostgREST for ToolJet Database (`tooljet_db`), reached only by the server |
| `internal-tools-db` | PostgreSQL 16 with `tooljet_production`, `tooljet_db` and `sample_db` |
| `internal-tools-valkey` | Valkey with `noeviction` and append-only persistence, password protected. The password is written to a config file on tmpfs, never passed in argv, and the healthcheck passes it through `VALKEYCLI_AUTH`. |
| `internal-tools-bootstrap` | one-shot Node job using the ToolJet image's Node 22 (script embedded from `bootstrap/bootstrap.mjs`) |

`TOOLJET_HOST` comes from `SEALED_PUBLIC_URL_TOOLS`, which the composer is asked to set to
`https://tools.<ip-with-dashes>.sslip.io` (or the custom domain); see interface change 1. Until
it does, internal-tools-server and the bootstrap stop at their `:?` guard, on purpose.

Hardening beyond upstream: every workspace gets a sample PostgreSQL data source. Upstream points
it at the metadata server with the superuser password; here it uses the `tooljet_sample` role
(created when the data directory is first initialised, owner of `sample_db`, not a superuser),
and the server process does not keep `PGPASSWORD` in its environment, so data sources that users
create cannot fall back to the superuser password. The same init script creates `tooljet_production`
and `tooljet_db` before ToolJet does (its createdb step skips existing databases) and revokes
`CONNECT` and `TEMPORARY` on both from `PUBLIC`, so the sample role, whose credentials every
workspace builder can read, reaches only `sample_db`; ToolJet grants `CONNECT` on `tooljet_db` to
its own per-workspace roles. `tests/db-init.test.mjs` runs the script on a throwaway PostgreSQL.
`tooljet_sample` keeps `CREATEDB` because ToolJet runs `createdb sample_db` as that role on every
boot, and PostgreSQL checks that privilege before it reports an existing database. PostgREST and
`TOOLJET_DB_USER` still use the superuser, as upstream does; a narrower authenticator role is an
open item.

## Secrets

| name | generated as | used for |
|---|---|---|
| `LOCKBOX_MASTER_KEY` | hex32 | encrypts data source credentials (do not change after first boot) |
| `SECRET_KEY_BASE` | hex32 | signs session tokens |
| `PGRST_JWT_SECRET` | hex32 | ToolJet to PostgREST requests |
| `PGPASSWORD` | hex32 | postgres superuser of `internal-tools-db` |
| `SAMPLE_DB_PASSWORD` | hex32 | `tooljet_sample` role |
| `REDIS_PASSWORD` | hex32 | `internal-tools-valkey` |
| `ADMIN_EMAIL` | supplied by the customer | first admin |
| `ADMIN_PASSWORD` | supplied by the customer | first admin, 8 to 100 characters |

## Bootstrap and sign-up

`POST /api/onboarding/setup-super-admin` creates the first admin and the default workspace, but
only while the instance has no users: whoever calls it first owns the instance. Two things keep
that first admin ours:

1. The route stays closed until the bootstrap is done. internal-tools-server starts ToolJet on the
   setup port 3001, which no Caddy route points at, and moves it to the route port 3000 only after
   `internal-tools-bootstrap/done.json` appears on the bootstrap volume (mounted read-only into the
   server). Until then the tools URL answers 502. The healthcheck accepts either port.
2. The bootstrap fails closed if someone else got in first. Other containers on the shared apps
   network can still reach the setup port (interface change 7 asks for per-app networks). If one
   of them calls `setup-super-admin` first, the endpoint answers 403 to the bootstrap, the admin
   cannot log in, the job fails and `done.json` is never written, so the route never opens onto
   that instance. Delete the internal-tools data and deploy again.

The `internal-tools-bootstrap` job (one-shot, `restart: on-failure`) creates the admin (or, on a
re-run, logs in), checks that the admin session can list apps, checks that self sign-up is
refused, writes `done.json`, then waits for ToolJet on port 3000 and probes sign-up there again.
On every later start it only re-runs that read-only sign-up probe. Sign-up itself is closed by
`DISABLE_SIGNUPS=true` and `SSO_DISABLE_SIGNUPS=true` in the measured environment, so it cannot be
re-opened from the UI. New users join by invitation; with no SMTP configured the admin copies the
invite link from the Users page.

A residual race: two callers that reach `setup-super-admin` at the same moment could both pass
ToolJet's first-user check. Only containers on the apps network can try that, and the bootstrap
does not yet list the workspace's users to catch it (the response shape of
`GET /api/organization-users` was not confirmed from source).

## Telemetry and outbound calls

`DISABLE_TOOLJET_TELEMETRY=true` stops the daily usage report to `hub.tooljet.io/telemetry`.
`TOOLJET_MARKETPLACE_URL` and `TJ_LICENSE_TRIAL_API` point at a loopback sink so marketplace plugin
downloads and trial requests fail at once. Sentry and OpenTelemetry stay unset or off. The
first-admin setup also posts the admin's name and email to `hub.tooljet.io/subscribe`; that call
has no switch and fails closed at the egress proxy (one blocked count). The 3.20 server has no
update check (`CHECK_FOR_UPDATES` from older docs is not read). Browser-side loads are outside
the VM's egress control; see "Frontend bundle" below.

## Frontend bundle

Browser-side requests leave from the user's browser, not the VM, so the egress policy does not
cover them. The CE web app in the upstream image (`app/frontend/build`, streamed from
`tooljet-ce@sha256:46d1c621...` with `crane export`, 2026-10-28) was searched for absolute URLs and
analytics calls:

- posthog-js is bundled, but neither the frontend bundle nor the server `dist` contains a PostHog
  project key (`phc_...`), so it has nothing to send to.
- The HubSpot form submit (`api.hsforms.com`) after sign-in runs only when `SSO_HUBSPOT_FORM_ID`
  and its portal id are configured; neither is set here.
- Some widgets load from third parties when they are used: map tiles (OpenStreetMap, CARTO,
  Stadia, Esri, Google Maps, and Mapbox with its `events.mapbox.com` telemetry when a Mapbox token
  is configured), fonts (`fonts.googleapis.com`, `fonts.openmaptiles.org`), script CDNs
  (`cdn.jsdelivr.net`, `unpkg.com`, `cdnjs.cloudflare.com`, `cdn.plot.ly`, for example for Pyodide,
  the terminal widget and charts), and plugin schemas from `raw.githubusercontent.com`. Builders
  who need a fully offline UI should avoid those widgets.

The image has no `app/frontend/build/ee` or `app/server/dist/ee` directory; the bundle itself was
not otherwise checked for enterprise features.

## Acceptance (A6)

`scripts/a6-internal-tools.sh` loads the UI, logs in, creates an app with `POST /api/apps`, and
finds it in the app list and at `GET /api/apps/:id`:

```sh
TOOLS_URL=https://tools.34-1-2-3.sslip.io ADMIN_EMAIL=... ADMIN_PASSWORD=... GATE_BASIC='sealed:...' \
  catalog/apps/internal-tools/scripts/a6-internal-tools.sh
```

ToolJet authenticates with a cookie, so HTTP basic auth for the gate (`GATE_BASIC`, user `sealed`
and the gate password) works next to it. `A6_CLEANUP=1` deletes the app afterwards.

## Development

```sh
cd catalog/apps/internal-tools
pnpm install --ignore-workspace --frozen-lockfile
pnpm test        # embed check, schema, fragment rules, docker compose config, bootstrap, A6, image checks
pnpm run embed   # after editing bootstrap/bootstrap.mjs
SEALED_COMPOSER_DIR=<ws/composer checkout> pnpm test   # also runs the real composer
```

The tests run the bootstrap and A6 code against an in-memory ToolJet (`tests/lib/fake-tooljet.mjs`)
that applies the same guards (first-user-only setup, sign-up guard before validation, cookie and
workspace header). `tests/server-entrypoint.test.mjs` runs the server's entrypoint under every
POSIX shell on the machine with a stand-in for ToolJet to check the setup-port switch, and
`tests/db-init.test.mjs` runs the database init script on a throwaway local PostgreSQL. When the
composer source is available, `sealed-compose lint` must report only the unbuilt tooljet digest
(D-028), and a composed stack is checked for the Caddyfile, the read-only `done.json` mount and the
healthcheck; a todo test tracks interface change 1. `tests/contract.test.mjs` builds the derived
image, checks its file list against `license_exclusions`, boots the stack and runs the bootstrap
and A6 against the real ToolJet; it runs only with `SEALED_CONTRACT=1` and a Docker daemon.
