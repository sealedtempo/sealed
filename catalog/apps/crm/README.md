# crm: Twenty

[Twenty](https://github.com/twentyhq/twenty) v2.52.0, an open-source CRM (companies, people,
opportunities, tasks, notes) with REST and GraphQL APIs. Route `crm`, behind the Sealed gate.
Metered in app hours from heartbeats.

## Release status: blocked

- D-019 (licensing): the official image contains files under the Twenty.com Commercial License,
  and some of them run without a key. That license forbids redistribution, and the release job
  mirrors the image. The composer lint refuses this app (`license-exclusions`) until the lead
  decides; see LICENSE-NOTICE and "Enterprise code" below.
- Interface change 6 (gate): the basic-auth gate breaks Twenty after login (see "Gate").
- Interface change 1: the composer does not set `SEALED_PUBLIC_URL_CRM` yet, so crm-server,
  crm-worker and crm-bootstrap stop at their `:?` guard.

## Pins

| image | source | digest (index) | license |
|---|---|---|---|
| twenty | `docker.io/twentycrm/twenty:v2.52.0` | `sha256:20b1010a975c42954d9f90698564795daf106da964bc95028836b09a8f424839` | AGPL-3.0-only (see LICENSE-NOTICE) |
| postgres | `docker.io/library/postgres:16.15` | `sha256:1beaa3084eee2676f20a9cd9928f0bf2c5bf674f8e49f81017912183d377c61c` | PostgreSQL |
| valkey | `docker.io/valkey/valkey:9.0.7` | `sha256:7e1deda01b64ece3167d370ab5be3452d29734feec22cbcbc69b3a64f6859d6d` | BSD-3-Clause |

All three were resolved with `crane digest` on 2026-10-28. Twenty v2.52.0 is the upstream tag
`twenty/v2.52.0` (commit `62c9c99746abbe3392de76ba77fd32cc93883335`). Twenty v2.34 and later
need PostgreSQL 15 or newer.

## Services

| service | what it runs |
|---|---|
| `crm-server` | Twenty API and web UI. Its entrypoint runs `database:init` (first boot), `upgrade` and the cron registration, then `node dist/main`: on the setup port 3001 until `crm-bootstrap/done.json` exists, then on port 3000, the route port. Primary service and route target. |
| `crm-worker` | the same image with `yarn worker:prod` (BullMQ jobs), migrations and cron registration off |
| `crm-db` | PostgreSQL 16, database `default`, data in volume `crm-db-data` |
| `crm-valkey` | Valkey with `noeviction` (BullMQ needs it) and append-only persistence on `crm-valkey-data`, password protected because the apps network is shared. The password is written to a config file on tmpfs, never passed in argv, and the healthcheck passes it through `VALKEYCLI_AUTH`. |
| `crm-bootstrap` | one-shot Node job using the Twenty image's Node 24 (script embedded from `bootstrap/bootstrap.mjs`) |

This follows `packages/twenty-docker/docker-compose.yml` at the tag, with Redis replaced by
Valkey (D-020), images by digest, no published ports and data on the encrypted data disk.
Server and worker share `crm-local-storage` (`STORAGE_TYPE=local`) and run as uid 1000.

`SERVER_URL` must be exactly the URL users open. The fragment reads it from
`SEALED_PUBLIC_URL_CRM`, which the composer sets to `https://crm.<ip-with-dashes>.sslip.io` (or the
custom domain). The connection strings for Postgres and Valkey are built from secrets at start by
the entrypoint wrapper and the raw secret variables are unset before Twenty starts.

## Secrets

| name | generated as | used for |
|---|---|---|
| `ENCRYPTION_KEY` | base64-32 | Twenty's encryption key (OAuth tokens, signing keys, TOTP secrets). Losing it loses those secrets. |
| `PG_DATABASE_PASSWORD` | hex32 | postgres user of `crm-db` (hex because it is placed unencoded in the URL) |
| `VALKEY_PASSWORD` | hex32 | `crm-valkey` |
| `ADMIN_EMAIL` | supplied by the customer | first admin |
| `ADMIN_PASSWORD` | supplied by the customer | first admin, 8 to 50 characters |

## Bootstrap and sign-up

Twenty makes the first account that signs up on an instance without a server admin its server
admin (full admin panel and impersonation), and anyone may sign up while no workspace exists.
Two things keep that first account ours:

1. The route stays closed until the bootstrap is done. crm-server starts Twenty on the setup
   port 3001, which no Caddy route points at, and moves it to the route port 3000 only after
   `crm-bootstrap/done.json` appears on the bootstrap volume (mounted read-only into crm-server).
   Until then the crm URL answers 502. The healthcheck accepts either port so the worker and the
   bootstrap can start.
2. The bootstrap fails closed if anyone else got in first. Other containers on the shared apps
   network can still reach the setup port (interface change 7 asks for per-app networks), so
   the job checks the outcome: its admin must hold both server admin flags, be the only
   workspace member, the only server admin (`getServerAdmins`) and the only user
   (`adminPanelRecentUsers`), and its workspace must be the only one
   (`adminPanelTopWorkspaces`). Any failure stops the job before the API key and `done.json`,
   so the route never opens onto an instance someone else controls. There is no repair: delete
   the crm data and deploy again.

The `crm-bootstrap` job (one-shot, `restart: on-failure`):

1. waits for `GET /healthz` on `http://crm-server:3001`;
2. calls `signUp` and `signUpInNewWorkspace` (display name `CRM`), exchanges the login token with
   `getAuthTokensFromLoginToken` using the public origin, and checks `currentUser` for the server
   admin flags;
3. calls `activateWorkspace` (builds the workspace schema and demo data; workspaces that are never
   activated are deleted after 7 days by Twenty's cleaner);
4. sets `isPublicInviteLinkEnabled: false`, then runs the sole-owner checks above;
5. creates an API key named `sealed-customer` with the Admin role (365 days) and writes it to
   `crm-bootstrap/api-key.json` (mode 0600, on the encrypted disk) for the customer;
6. checks `GET /client-config`: every listed switch must be present with its expected value
   (a renamed or dropped field fails too), `authProviders.sso` must be empty and `serverUrl`
   must be the public URL; then it writes `done.json`, waits for Twenty on port 3000 and checks
   the client config there again.

Every step is idempotent: a re-run after a crash logs in instead of signing up, waits for an
activation that is still running, and keeps an API key that was already written. On every later
start (for example after a reboot or an upgrade) the job only re-checks the client config on port
3000, read-only, so a release whose defaults changed fails loudly. With
`IS_MULTIWORKSPACE_ENABLED=false`, Twenty refuses `signUp` and new workspaces once one workspace
exists, so sign-up is closed after the bootstrap. Remaining ways in are admin-controlled: email
invitations and approved access domains.

Email uses the `LOGGER` driver: invitation and password-reset mails are not delivered. Invite
users from Settings and share the invite link by hand.

## Gate

INTERFACES section 14 puts every app UI behind `basic_auth`, and the composer allows
`bearer-passthrough` only for the gateway route, so the manifest uses `auth: gate`. That does not
work with Twenty: its web app and API send `Authorization: Bearer <token>` on every signed-in call,
Twenty reads its token from nowhere else, and the gate refuses that header (and strips it on
requests it lets through). The login page loads; everything after login fails. Interface change 6
asks for a cookie or `forward_auth` gate, or `bearer-passthrough` for crm. The preconditions the
review set for the second option are in place: the route stays closed until `done.json`, and the
bootstrap fails closed on a foreign server admin. `tests/catalog.test.mjs` has a todo test that
passes once the composer accepts `bearer-passthrough` for crm; then the manifest change is one line.

## Telemetry, enterprise code and outbound calls

`telemetry_off_env` sets `TELEMETRY_ENABLED=false` (upstream default is on, and it sends the
admin's email on sign-up), `ANALYTICS_ENABLED=false`, `ALLOW_REQUESTS_TO_TWENTY_ICONS=false`,
`MARKETPLACE_CATALOG_SYNC_CRON_ENABLED=false`, `ENTERPRISE_API_URL=` (empty),
`SUPPORT_DRIVER=NONE`, `IS_BILLING_ENABLED=false` and `IS_CONFIG_VARIABLES_IN_DB_ENABLED=false`
(env is the only configuration source; the admin panel cannot store an enterprise key or re-enable
telemetry). The fragment also turns off Gmail, Google Calendar, Microsoft, IMAP/SMTP/CalDAV, SSO
providers, address autocomplete, the onboarding AI chat, logic functions and the code interpreter.
`ENTERPRISE_KEY`, `APP_SECRET`, Sentry, ClickHouse, Stripe and every AI provider key are never set.

Enterprise code (D-019, escalated): Twenty has no enterprise directory. Files marked
`@license Enterprise` are compiled into the image with the AGPL code, and some of them run on
every start without a key (module setup, entitlement checks, billing wiring with billing off,
enterprise cron jobs that return early). Features that need a key (SSO, row-level permissions,
audit logs, more than five workspaces) stay locked. The Commercial License restricts production
use and forbids redistribution, so this app is not mirrored or published until the lead decides
between a build without those files and a recorded exemption. `license_exclusions` stays empty
because nothing is left out of the image.

The egress policy allows no host. The Docker Hub version check in the admin panel and the
`twenty-icons.com` workspace logo fetch at bootstrap have no off switch; both fail closed and show
as blocked counts.

## Acceptance (A6)

`scripts/a6-crm.sh` creates a company, a person and an opportunity with the REST API and checks
the relations:

```sh
CRM_URL=https://crm.34-1-2-3.sslip.io API_KEY_FILE=api-key.json GATE_BASIC=sealed:<gate password> \
  catalog/apps/crm/scripts/a6-crm.sh
```

Instead of `API_KEY_FILE` it accepts `API_KEY`, or `ADMIN_EMAIL` and `ADMIN_PASSWORD` to mint a
one-day key and revoke it afterwards. `GATE_BASIC` is sent on calls without a Twenty token
(`/healthz`, the admin login). Calls with a token send it as `Authorization: Bearer`, so through
the public URL A6 passes only once interface change 6 lands; with today's gate the helper stops at
the first REST call and says so. For A11, read the same ids back after the reboot.

## Development

```sh
cd catalog/apps/crm
pnpm install --ignore-workspace --frozen-lockfile
pnpm test        # embed check, schema, fragment rules, docker compose config, bootstrap, A6
pnpm run embed   # after editing bootstrap/bootstrap.mjs
SEALED_COMPOSER_DIR=<ws/composer checkout> pnpm test   # also runs the real composer
```

The tests run the real bootstrap and A6 code against an in-memory Twenty (`tests/lib/fake-twenty.mjs`)
that applies Twenty's single-workspace, server-admin, admin-panel guard, origin and token rules
and returns a v2.52-shaped client config, plus a stand-in for the Caddy site
(`tests/lib/fake-gate.mjs`). `tests/server-entrypoint.test.mjs` runs crm-server's entrypoint
under every POSIX shell on the machine with a stand-in for Twenty to check the setup-port switch.
When the composer source is available (in this checkout after the merge, or through
`SEALED_COMPOSER_DIR`), `sealed-compose lint` must report only the D-019 block, and a composed
stack is checked for the Caddyfile, the read-only `done.json` mount and the healthcheck. Two todo
tests track interface changes 1 and 6. `tests/contract.test.mjs` boots the pinned images with
Docker and runs the bootstrap and A6 against the real Twenty; it runs only with
`SEALED_CONTRACT=1` and a Docker daemon (CI and the dev CVM).

## Known limits

- The bootstrap API key sits in `crm-bootstrap/api-key.json` on the encrypted disk. Nothing exposes
  bootstrap outputs to the customer yet (agent or console); until then the customer creates keys
  in Settings, Developers, API.

- Twenty's `/healthz` only shows that Node is listening; it does not check Postgres, Valkey or the
  worker.
- Email and calendar sync stay off even if the customer adds provider hosts to egress, because the
  provider switches are fixed in the measured fragment. Turning them on needs a customer option in
  the public config (requested in the build note).
- Every restart runs Twenty's `upgrade` command and two cache flushes, so restarts are slower than a
  plain Node start.
