# crm: EspoCRM

[EspoCRM](https://github.com/espocrm/espocrm) 10.0.11, an open-source CRM (accounts, contacts,
leads, opportunities, cases, calls, meetings, tasks) with a REST API and API-key users, on
PostgreSQL. Route `crm`, behind the Sealed gate. Metered in app hours from heartbeats.

Until 2026-10-28 this app was Twenty v2.52.0. Decision D-049 withdrew that (the official Twenty
image carries files under Twenty's commercial license), and D-049a below records why crm is now
EspoCRM instead of a stripped Twenty build.

## Release status

- D-028: `images/espocrm` is built by the runtime image workflow; until its digest is pinned in
  `manifest.yaml`, `sealed-compose lint` reports exactly `unbuilt-image images[0].digest`, which
  blocks the release. Nothing else blocks it.
- Brief item 8: the composer of this checkout does not set `SEALED_PUBLIC_URL_CRM` yet, so
  `sealed-espocrm` stops every EspoCRM service with a clear message until it does (a todo test
  flips when it lands).

## D-049a

Decision text (for DECISIONS.md):

> **D-049a 2026-10-28 crm is EspoCRM 10.0.11, not a stripped Twenty**
> - Option A (Twenty v2.52.0 without its `@license Enterprise` files) is not feasible as removal
>   plus small stubs. At commit 62c9c99 576 files carry the marker; 290 AGPL production files
>   import 242 of them directly and 486 are reachable from AGPL production code. The imports sit
>   in core paths: the ORM repository every record read and write goes through (record sharing,
>   row-level permissions, validation rules), the query runners behind REST and GraphQL (usage
>   recording, share-with), the core module list, the ORM module and manager (EnterpriseModule,
>   EnterprisePlanService), sign-up (BillingService), TypeORM relations of the role and
>   workspace entities, the metadata engine (the MIT `twenty-shared` package lists the
>   enterprise metadata names, which 65 AGPL server files and the migration builder, validators
>   and runners handle), and the front end's current-user query asks for the row-level fields.
>   Stripping means about 240 replacement files that satisfy the original types plus edits to
>   the core: a fork to redo for every release, while the Commercial License claims rights in
>   modifications of the marked files. It also could not be built or run here (no Docker daemon,
>   and a build means running Twenty's own yarn release and scripts).
> - Option B: crm ships EspoCRM 10.0.11 (AGPL-3.0-or-later in every application file, one
>   module, no paid extensions in the release, PostgreSQL 15 or later, REST API with API-key
>   users, no usage telemetry). Krayin and SuiteCRM run only on MySQL or MariaDB and Frappe CRM
>   on MariaDB with Redis, servers that rule 9 does not allow in app images; Odoo CE is an ERP
>   suite far larger than a CRM.
> - The image (`catalog/apps/crm/images/espocrm`) is Debian trixie packages from
>   snapshot.debian.org 20261027T000000Z (Apache httpd, PHP 8.4 with mod_php, Node.js 20 for
>   the bootstrap job) plus the EspoCRM release zip checked by sha256. Its build fails if an
>   application PHP file lacks the AGPL header, a Composer package is outside the license list,
>   or any file carries an `@license Enterprise` marker. PHP counts as an OS package (PHP-3.01 is
>   on the system list). Debian's PHP packages also name the Zend Engine License 2.00 for the
>   Zend directory, which the lint does not know: it is accepted for OS packages under this
>   decision (FSF-free, BSD-style; PHP upstream has accepted relicensing it as BSD-3-Clause).
> - EspoCRM's calls home (version and extension checks, the admin-panel iframe from
>   s.espocrm.com), WebSocket, extension uploads and upgrades from the UI are fixed off in
>   `data/config-override.php` on every start; `telemetry_off_env` lists them and the entrypoint
>   refuses to start if they differ.
> - The image drops the standard `Authorization` header, because EspoCRM reads it as a login
>   before its own cookie. The gate's Basic credentials never reach EspoCRM in either gate shape
>   (basic_auth or forward_auth, D-044); EspoCRM's own auth (Espo-Authorization, the auth-token
>   cookie, X-Api-Key) is untouched.

## Why not Twenty (option A, investigated first)

Time box: about three hours of agent work (brief item 24). Method: a blobless sparse clone of
`twentyhq/twenty` at tag `twenty/v2.52.0` (commit `62c9c99746abbe3392de76ba77fd32cc93883335`)
under the worktree's `tmp/`, read only; nothing from it was run. `tools/twenty-enterprise-audit.py`
resolves every TypeScript import of twenty-server, twenty-front and twenty-shared (aliases
`src/*`, `test/*`, `@/*`, `~/*`, `twenty-shared/*`) and reproduces the numbers:

```sh
git clone --filter=blob:none --no-checkout https://github.com/twentyhq/twenty.git tmp/twenty
git -C tmp/twenty checkout 62c9c99746abbe3392de76ba77fd32cc93883335
python3 -I catalog/apps/crm/tools/twenty-enterprise-audit.py tmp/twenty --json tmp/twenty-audit.json
```

| measure | value |
|---|---|
| files carrying `/* @license Enterprise */` (two of them after their imports) | 576: 503 server `src`, 12 server tests, 56 front, 5 in the MIT `twenty-shared` package |
| largest areas | billing 187, record-share 71, validation-rule 35, usage 29, billing-webhook 25, row-level-permission-predicate 19, workspace-migration 19, enterprise 19, sso 18, event-logs 16, twenty-orm utils 13 |
| AGPL production files that import a marked file | 290 (plus 145 test files) |
| marked files imported by AGPL production code (the stub surface) | 242, about 270 imported symbols |
| marked files reachable from AGPL production code | 486 of 576 |
| AGPL core-path files among the importers | 54 |

How the marked code is wired into the core (each needs an edit or a stub with the original's
types):

- Modules: `core-engine.module.ts` imports 8 marked modules (Billing, BillingWebhook, AppBilling,
  Usage, RecordShare, RowLevelPermission, WorkspaceSso, EventLogsViewer); `twenty-orm.module.ts`
  imports `EnterpriseModule` and the billing entitlements cache; `metadata-engine.module.ts`
  imports `ValidationRuleModule`; `app.module.ts` installs the usage request middleware; `main.ts`
  imports the usage recorder.
- Every record read and write: `twenty-orm/repository/workspace-repository.ts` imports 17 marked
  files (record-share access policies, inherited readability, row-level filters, validation
  rules); `workspace-orm.manager.ts` asks `EnterprisePlanService` whether validation rules apply.
- REST and GraphQL: `common-base-query-runner.service.ts` (every query) records usage through
  marked services; the create-many runner resolves `shareWith`; both API exception handlers
  import marked record-share and validation-rule exceptions.
- Auth and workspaces: `sign-in-up.service.ts` uses `BillingService` and `EnterprisePlanService`;
  `workspace.entity.ts` has a TypeORM relation to the marked SSO identity provider entity, and
  `role.entity.ts` to the marked row-level permission predicate entities.
- Metadata engine: `ALL_METADATA_NAME` in twenty-shared includes `rowLevelPermissionPredicate`,
  `rowLevelPermissionPredicateGroup` and `validationRule`; the flat-entity maps, workspace cache
  keys and the workspace migration orchestrator, builders, validators and action handlers are
  generic over that list, and 65 AGPL server files name these metadata types.
- Front end: `userQueryFragment.ts` (the current-user query) spreads marked row-level permission
  fragments, `SettingsRoutes.tsx` routes to marked SSO and domain pages, and record creation and
  select inputs call marked RLS hooks. The server's GraphQL schema therefore has to keep those
  fields even if their code goes.

So "remove the files and stub a few registrations" does not leave a working core: the stubs would
have to reimplement the API surface of about 240 files inside the paths that serve companies,
people, opportunities, API keys and REST, and be redone for every Twenty release (new marked
files appear in most releases). The Commercial License also says Twenty keeps the rights in
modifications and patches of the marked files, so stubs written against them carry a licensing
question that a clean CRM does not. Building and running such a fork was not possible here
either: there is no Docker daemon, and a build runs Twenty's yarn release and package scripts.
Option A was therefore stopped after the source audit, well inside the box.

## CRM candidates (option B)

The brief's criteria: license with no enterprise code shipped, self-host maturity, API for
company, contact and deal, telemetry controls, PostgreSQL. A database server under GPL-2.0
(MySQL, MariaDB) is not on the rule 9 list for app images, so PostgreSQL support is decisive.
Facts below were read on 2026-10-28 from the upstream repositories and docs.

| | EspoCRM 10.0.11 | Krayin 2.2 | SuiteCRM 8.10 | Frappe CRM 1.x | Twenty v2.52.0 |
|---|---|---|---|---|---|
| license | AGPL-3.0-or-later (every application file), section 7(b) attribution | MIT | AGPL-3.0 | AGPL-3.0 | AGPL-3.0 plus commercial-license files in the core |
| enterprise code shipped | none (one module, paid extensions are separate downloads) | none known | none known | none known | 576 marked files |
| database | MySQL 8, MariaDB 10.6, **PostgreSQL 15+** | MySQL 8.0.32+, MariaDB 11.4+ | MariaDB, MySQL | MariaDB (its compose file) | PostgreSQL |
| other servers | none (optional WebSocket daemon, off) | none | none | Redis | Redis (Valkey in the old package) |
| API for company, contact, deal | REST `Account`, `Contact`, `Opportunity`, API users with X-Api-Key or HMAC | separate REST API package | REST v8 (JSON:API) | Frappe REST | REST and GraphQL |
| maturity | since 2014, 3.5k stars, releases every few weeks (10.0.3 to 10.0.11 from July to October 2026), official Docker image | active | long-lived (SugarCRM CE fork) | young, on the Frappe framework | very active |
| telemetry and calls home | no usage telemetry; version checks and an admin-panel iframe from s.espocrm.com, both switchable | not evaluated | not evaluated | not evaluated | telemetry on by default (switchable) |
| verdict | **chosen** | no PostgreSQL | no PostgreSQL | no PostgreSQL, needs Redis | D-049 |

Odoo Community (LGPL-3.0, PostgreSQL) was not taken further: it is a full ERP suite, its image
and memory needs are several times EspoCRM's, and its community modules call odoo.com services
that would need their own audit.

What was checked in EspoCRM 10.0.11 itself (the release zip as EspoCRM's own image ships it,
streamed with `crane export`, nothing executed):

- All 2722 PHP files under `application/` carry the AGPL header with the section 7(b) term
  (keep the "EspoCRM" word in the legal notices). `application/Espo/Modules` holds only `Crm`.
- `vendor/composer/installed.json`: 117 packages, 105 MIT, 3 BSD-3-Clause, 3 BSD-2-Clause,
  1 Apache-2.0, 1 MIT OR Apache-2.0, 4 LGPL (dompdf and friends, picqer barcode). `client/lib`
  holds jQuery, Backbone, Handlebars, Ace (BSD-3-Clause) and similar permissive libraries.
- Outbound calls in the server code: `Tools/AdminNotifications/LatestReleaseDataRequester.php`
  fetches `s.espocrm.com/release/latest` (URL base64-encoded in the source) for the daily
  version and extension checks, gated by `adminNotifications*`; the admin panel's front end
  embeds an iframe from `s.espocrm.com` with the version and site URL, gated by
  `adminPanelIframeDisabled`. Google Maps, OAuth providers, reCAPTCHA, S3 storage, LDAP, IMAP
  and SMTP run only when an admin configures them. No usage telemetry.
- Auth (`Espo\Core\Api\Auth`): Espo-Authorization first, then a standard `Authorization: Basic`
  header (PHP_AUTH_USER), and the `auth-token` cookie only when neither is present; X-Api-Key and
  HMAC for API users. No self sign-up: users are created by admins. The web installer lives in
  `install/` and `public/install/`.

## Pins

| item | pin |
|---|---|
| EspoCRM release | `https://www.espocrm.com/downloads/EspoCRM-10.0.11.zip`, sha256 `cdd04f7efa52a59025ef824c75b06e0a84cf986724a8c5bc4b56fcd2ce8e0ab1` (from `espocrm/espocrm-docker` tag 10.0.11, commit `a2f3e9cba6edb596afdafca2b9ac6d639fd29c5c`); source tag `10.0.11`, commit `32d559ba86d3be607599d1325c359668c1178850` |
| image base | `docker.io/library/debian:trixie-20261020-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |
| Debian packages | snapshot.debian.org `20261027T000000Z` (trixie, trixie-updates, trixie-security): PHP 8.4.27, Node.js 20.19.2, Apache 2.4 |
| espocrm image | `build:images/espocrm`, digest pending (D-028) |
| postgres | `docker.io/library/postgres:16.15`, index `sha256:1beaa3084eee2676f20a9cd9928f0bf2c5bf674f8e49f81017912183d377c61c` (linux/amd64 `sha256:b95b87e93ceb7594715d5c71fb6e09f6fc878851ab537735d617325eb9ba8b1b`) |

Digests were resolved with `crane digest` on 2026-10-28.

## Image (`images/espocrm`)

- `Dockerfile`: two stages from the pinned Debian base. `fetch` downloads the release zip over
  HTTPS, checks its sha256 and version, removes the web installer, moves `data/`, `custom/` and
  `client/custom/` into skeletons, and runs the license gates. The runtime stage installs only
  Debian packages from the snapshot, copies the release, and checks itself at build time: the
  PHP extensions EspoCRM needs, Node 20, `apache2 -t`, and the override files that
  `sealed-espocrm` writes (`php -l`, their values, mode 0600).
- `sealed-espocrm.sh`: the entrypoint (POSIX sh). As root it only gives the three volume
  directories (and the bootstrap state directory) to www-data on first use, then re-runs itself
  through `setpriv` as uid 33 with no capabilities and `no_new_privs`. It checks
  `SEALED_PUBLIC_URL_CRM`, `PG_DATABASE_PASSWORD` and the seven `telemetry_off_env` switches with
  shell builtins (no secret reaches another process's argv), seeds missing skeleton files, and
  writes `data/config-override.php` (public URL, switches) and
  `data/config-internal-override.php` (database, mode 0600) on every start. EspoCRM merges both
  over its own config, so the admin panel cannot turn the switches back on. Modes: `server`
  (clear cache and `migrate` when installed, then Apache), `daemon` (`php daemon.php` once
  installed), `bootstrap <cmd>`, `write-config <dir>` (build check).
- `apache-sealed.conf`: Apache on 8080 with mod_php (prefork), document root `public/`,
  `/client/` alias, `.htaccess` only under `public/`, no PHP from `client/` (its `custom/` is
  writable), `RequestHeader unset Authorization early`, client addresses from Caddy only
  (`RemoteIPInternalProxy 172.30.0.4`), errors to stderr, no access log.
- `php-sealed.ini`: EspoCRM's recommended limits (256M memory, 50M uploads, 180 s).

## Services

| service | what it runs |
|---|---|
| `crm-server` | Apache with EspoCRM on 8080, the route port. Primary service and route target. |
| `crm-daemon` | EspoCRM's job daemon (`php daemon.php`), after the bootstrap has finished |
| `crm-db` | PostgreSQL 16, database and owner `espocrm`, data in `crm-db-data` |
| `crm-bootstrap` | one-shot Node job in the same image (script embedded from `bootstrap/bootstrap.mjs`) |

Volumes: `crm-data` (EspoCRM's `data/`: config, uploads, logs, cache), `crm-custom` (custom
entities and layouts from the admin panel), `crm-client-custom`, `crm-db-data`, `crm-bootstrap`
(`api-key.json`, `done.json`). All are on the encrypted data disk. The three EspoCRM services
mount the same three data volumes.

## Secrets

| name | generated as | used for |
|---|---|---|
| `PG_DATABASE_PASSWORD` | hex32 | `espocrm` database role; written into `data/config-internal-override.php` |
| `ADMIN_PASSWORD` | `password` (24 letters and digits) unless the customer sets one | EspoCRM administrator `admin`, 8 to 128 characters; needed only on the first start |

EspoCRM generates its own `passwordSalt`, `cryptKey` and `hashSecretKey` during the install
(`config:populate`) and keeps them in `data/config-internal.php` on the encrypted disk.

## Bootstrap

The `crm-bootstrap` job (one-shot, `restart: on-failure`), as www-data in the EspoCRM directory:

1. If EspoCRM is not installed: waits for `bin/command db:check`, then EspoCRM's CLI install
   (`config:populate`, `rebuild`, `create-admin-user admin`, `set-password` with the password on
   stdin, `populate-scheduled-jobs`, `app-check`, `isInstalled`), the same steps as EspoCRM's
   own image. The database settings come from the override file.
2. Checks the system switches with `config:get` (`adminExtensionUpload`, `adminUpgrade`,
   `adminUpgradeDisabled`, `siteUrl`).
3. Waits for crm-server, logs in as the admin and checks that the only accounts are the admin,
   its API user and EspoCRM's system user. Anything else fails closed: there is no repair,
   delete the crm data and deploy again.
4. Creates the role `Sealed API` (full access to Account, Contact, Lead, Opportunity, Case, Task,
   Call, Meeting, Document; no administration) and the API user `sealed-customer` with it.
   EspoCRM generates the key; the job writes `crm-bootstrap/api-key.json` (mode 0600) with the
   header name and the public API URL, and checks that the key can list accounts.
5. Checks the admin's view of `GET /api/v1/Settings`: every fixed switch present with its value
   and `siteUrl` equal to the public URL. Then writes `done.json`; the gate opens the route.

Every step is idempotent (a crash resumes, an existing role or API user is reused). On later
starts the job only re-checks the system switches and the anonymous settings, read-only and
without the admin password, so a customer who changes it in EspoCRM keeps a working restart.

## Gate

The route uses `auth: gate`. Before brief item 9 the composer renders Caddy `basic_auth` and
strips `Authorization`; with item 9 Caddy asks sealed-agent (`forward_auth`, D-044), which sets
the `sealed_gate` cookie. Both work: EspoCRM's web app authenticates with `Espo-Authorization`
and its `auth-token` cookie, API users with `X-Api-Key`, and none of them use the standard
`Authorization` header. A browser that passed the gate keeps sending its Basic credentials, and
EspoCRM would read them as a login before its cookie (entry points such as attachments and images
carry only the cookie), so the image drops that header. `tests/a6.test.mjs` shows both gate shapes
and what happens without the drop.

## Telemetry and outbound calls

`telemetry_off_env` (checked by the entrypoint, applied through `data/config-override.php`):
`ESPOCRM_CONFIG_USE_WEB_SOCKET=false`, `ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS=false`,
`ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS_NEW_VERSION=false`,
`ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS_NEW_EXTENSION_VERSION=false`,
`ESPOCRM_CONFIG_ADMIN_PANEL_IFRAME_DISABLED=true` (the override also points the iframe URL at
`about:blank`), `ESPOCRM_CONFIG_ADMIN_EXTENSION_UPLOAD=false`,
`ESPOCRM_CONFIG_ADMIN_UPGRADE_DISABLED=true`. The names follow EspoCRM's own image convention
for config variables. The egress policy allows no host.

## Acceptance (A6, A11)

`scripts/a6-crm.sh` creates an account, a contact linked to it and an opportunity linked to both
through the REST API, reads them back and checks the links (also through
`/Account/<id>/opportunities`):

```sh
CRM_URL=https://crm.34-1-2-3.sslip.io API_KEY_FILE=api-key.json GATE_BASIC=sealed:<gate password> \
  catalog/apps/crm/scripts/a6-crm.sh > a6-ids.json
# A11, after the reboot: the same records are still there
CRM_URL=... API_KEY_FILE=api-key.json GATE_BASIC=... catalog/apps/crm/scripts/a6-crm.sh --check a6-ids.json
```

Instead of `API_KEY_FILE` it accepts `API_KEY`, or `ADMIN_PASSWORD` (and `ADMIN_USERNAME`) to
work as the administrator. `GATE_BASIC` is sent on every call and the gate's cookie is kept.
`A6_CLEANUP=1` deletes the records at the end.

## Development

```sh
cd catalog/apps/crm
pnpm install --ignore-workspace --frozen-lockfile
pnpm test        # embed check, schema, fragment rules, composer lint and compose, image, bootstrap, A6
pnpm run embed   # after editing bootstrap/bootstrap.mjs
SEALED_CONTRACT=1 pnpm test   # also builds the image and boots it (Docker daemon, CI or the dev CVM)
```

- `tests/bootstrap.test.mjs` runs the real bootstrap against `tests/lib/fake-espocrm.mjs` (auth,
  settings visibility, API-key users and ACL as in the 10.0.11 source) and a `bin/command`
  stand-in (`tests/lib/fake-espo-command.mjs`) that share one state file, with the override
  files written by the real `sealed-espocrm`.
- `tests/image.test.mjs` runs `sealed-espocrm.sh` under every POSIX shell on the machine with
  stand-ins for `id`, `stat`, `chown`, `setpriv`, `php` and `apache2`, and checks the Dockerfile
  and the Apache configuration.
- `tests/a6.test.mjs` runs the A6 helper through `tests/lib/fake-gate.mjs` in both gate shapes.
- `tests/catalog.test.mjs` runs the real `sealed-compose lint` and `compose` from this checkout.
- `tests/audit.test.mjs` checks `tools/twenty-enterprise-audit.py` on a small Twenty-shaped tree.
- `tests/contract.test.mjs` builds the image and boots it with the pinned PostgreSQL, then runs
  the bootstrap and A6 against the real EspoCRM; only with `SEALED_CONTRACT=1` and Docker.

## Known limits

- The image has not been built or booted on this machine (no Docker daemon); the bootstrap and A6
  ran against fakes that follow the 10.0.11 source. The contract test covers the real thing.
- The API key sits in `crm-bootstrap/api-key.json` on the encrypted disk. Nothing exposes
  bootstrap outputs to the customer yet; until then the admin creates API users in
  Administration, API Users.
- Email is not configured: password-reset and notification mails are not sent until the admin
  sets up SMTP and the customer adds the host to egress (raw SMTP and IMAP need more than an
  allowlist entry, see `egress.yaml`).
- `espocrm` is the database owner and, through the official PostgreSQL image, a superuser in its
  own database server, as the earlier crm package did with Twenty.
- Data from the earlier Twenty-based crm is not migrated (no release of it was ever published).
