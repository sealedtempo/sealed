# crm: Twenty

[Twenty](https://github.com/twentyhq/twenty) v2.52.0, an open-source CRM (companies, people,
opportunities, tasks, notes) with REST and GraphQL APIs. Route `crm`, behind the Sealed gate.
Metered in app hours from heartbeats.

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
| `crm-server` | Twenty API and web UI on port 3000. Its entrypoint runs `database:init` (first boot), `upgrade` and the cron registration, then `node dist/main`. Primary service and route target. |
| `crm-worker` | the same image with `yarn worker:prod` (BullMQ jobs), migrations and cron registration off |
| `crm-db` | PostgreSQL 16, database `default`, data in volume `crm-db-data` |
| `crm-valkey` | Valkey with `noeviction` (BullMQ needs it) and append-only persistence on `crm-valkey-data`, password protected because the apps network is shared |
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

Until the first workspace exists, whoever reaches Twenty first becomes server admin. The
`crm-bootstrap` job therefore runs inside the VM against `http://crm-server:3000` as soon as the
server is healthy, and the crm route stays closed until it has written
`crm-bootstrap/done.json`. The job:

1. waits for `GET /healthz`;
2. calls `signUp` and `signUpInNewWorkspace` (display name `CRM`), exchanges the login token with
   `getAuthTokensFromLoginToken` using the public origin;
3. calls `activateWorkspace` (builds the workspace schema and demo data; workspaces that are never
   activated are deleted after 7 days by Twenty's cleaner);
4. sets `isPublicInviteLinkEnabled: false`;
5. creates an API key named `sealed-customer` with the Admin role (365 days) and writes it to
   `crm-bootstrap/api-key.json` (mode 0600, on the encrypted disk) for the customer;
6. checks `GET /client-config` for every switch that must be off and writes `done.json`.

Every step is idempotent: a re-run after a crash logs in instead of signing up, waits for an
activation that is still running, and keeps an API key that was already written. With
`IS_MULTIWORKSPACE_ENABLED=false`, Twenty refuses `signUp` and new workspaces once one workspace
exists, so sign-up is closed after the bootstrap. Remaining ways in are admin-controlled: email
invitations and approved access domains.

Email uses the `LOGGER` driver: invitation and password-reset mails are not delivered. Invite
users from Settings and share the invite link by hand.

## Telemetry, enterprise code and outbound calls

`telemetry_off_env` sets `TELEMETRY_ENABLED=false` (upstream default is on, and it sends the
admin's email on sign-up), `ANALYTICS_ENABLED=false`, `ALLOW_REQUESTS_TO_TWENTY_ICONS=false`,
`MARKETPLACE_CATALOG_SYNC_CRON_ENABLED=false`, `ENTERPRISE_API_URL=` (empty),
`SUPPORT_DRIVER=NONE`, `IS_BILLING_ENABLED=false` and `IS_CONFIG_VARIABLES_IN_DB_ENABLED=false`
(env is the only configuration source; the admin panel cannot store an enterprise key or re-enable
telemetry). The fragment also turns off Gmail, Google Calendar, Microsoft, IMAP/SMTP/CalDAV, SSO
providers, address autocomplete, the onboarding AI chat, logic functions and the code interpreter.
`ENTERPRISE_KEY`, `APP_SECRET`, Sentry, ClickHouse, Stripe and every AI provider key are never set.

Enterprise-licensed files are present in the image but never enabled (D-019, see LICENSE-NOTICE).

The egress policy allows no host. The Docker Hub version check in the admin panel and the
`twenty-icons.com` workspace logo fetch at bootstrap have no off switch; both fail closed and show
as blocked counts.

## Acceptance (A6)

`scripts/a6-crm.sh` creates a company, a person and an opportunity with the REST API and checks
the relations:

```sh
CRM_URL=https://crm.34-1-2-3.sslip.io API_KEY_FILE=api-key.json GATE_COOKIE='...' \
  catalog/apps/crm/scripts/a6-crm.sh
```

Instead of `API_KEY_FILE` it accepts `API_KEY`, or `ADMIN_EMAIL` and `ADMIN_PASSWORD` to mint a
one-day key and revoke it afterwards. Twenty sends `Authorization: Bearer` on every API call, so
the gate in front of `crm` cannot be HTTP basic auth on the same header; the helper passes the
gate with `GATE_COOKIE` or `GATE_HEADER`. For A11, read the same ids back after the reboot.

## Development

```sh
cd catalog/apps/crm
pnpm install --ignore-workspace --frozen-lockfile
pnpm test        # embed check, schema, fragment rules, docker compose config, bootstrap, A6
pnpm run embed   # after editing bootstrap/bootstrap.mjs
```

The tests run the real bootstrap and A6 code against an in-memory Twenty (`tests/lib/fake-twenty.mjs`)
that enforces the same single-workspace, origin and token rules. Booting the real stack needs
Docker and is part of the VM acceptance run.

## Known limits

- Twenty's `/healthz` only shows that Node is listening; it does not check Postgres, Valkey or the
  worker.
- Email and calendar sync stay off even if the customer adds provider hosts to egress, because the
  provider switches are fixed in the measured fragment. Turning them on needs a customer option in
  the public config (requested in the build note).
- Every restart runs Twenty's `upgrade` command and two cache flushes, so restarts are slower than a
  plain Node start.
