# Scraper

First-party web scraper for Sealed (replaces Apify). `scraper-runner` is a TypeScript service built on
[Crawlee](https://crawlee.dev) 3.18.2 with a small REST API and a server-rendered UI. Jobs crawl with
Cheerio (plain HTTP) or Playwright Firefox, extract fields with CSS selectors, and store runs and items in
the app's own Postgres. Results export as JSON or CSV. License: Apache-2.0.

Your data stays in your cloud account. Apps run in confidential VMs, we have no access path, and outbound
traffic only reaches destinations you approve. Confidential VMs do not stop physical attacks on the server,
bugs inside apps, or a cloud provider with physical access.

## In the VM

| service | image | role |
|---|---|---|
| `scraper-runner` | `scraper-runner-playwright` (built from `images/scraper-runner-playwright`) | API, UI, crawlers; port 8080, route `scraper` behind the password gate |
| `scraper-db` | `postgres:17.11-alpine` by digest | runs, items, events; volume `scraper-db-data` on the encrypted data disk |

- Egress: none by default (`egress.yaml`). Add the sites you want to crawl to `egressAdditions.scraper`
  as `host:port`, for example `example.com:443`. Every page fetch, robots.txt fetch and Firefox connection
  goes through sealed-egress (`HTTP_PROXY`); the runner refuses to start without it.
- Secrets: `SCRAPER_DB_PASSWORD` (generated, `hex32`), used by both services. It never leaves the VM.
- Metering: unit `pages`, source `callback`. Each successful page (final status below 400, item stored)
  counts once. Counts are batched into `POST http://sealed-agent:7070/v1/usage-events` with
  `{"app":"scraper","unit":"pages","quantity":N}`, every 5 seconds or every 50 pages. Unsent counts are
  kept and retried. Failed, skipped and robots-disallowed pages are not metered. No URLs or content are
  sent, only the count.

## Jobs

`POST /api/v1/jobs` with `content-type: application/json`:

| field | type | default | rules |
|---|---|---|---|
| `start_urls` | string[] | required | 1 to 100 public `http`/`https` URLs, no credentials, no private, loopback or link-local addresses, no single-label or `.internal`/`.local` names |
| `max_pages` | integer | 100 | 1 to 10000 requests per run |
| `crawler` | `cheerio` or `playwright` | `cheerio` | `playwright` only when the image has Firefox (`GET /api/v1/capabilities`) |
| `same_domain` | boolean | true | follow links on the same host name only (`same-hostname`); false follows every link, and sealed-egress still decides what is reachable |
| `extract` | {field: selector} | {} | up to 50 fields; names `[A-Za-z_][A-Za-z0-9_]*` (not `url`); selectors are CSS, checked when the job is created |
| `max_concurrency` | integer | 4 (cheerio), 2 (playwright) | 1 to 32 (cheerio), 1 to 4 (playwright) |
| `max_requests_per_minute` | integer | 60 | 1 to 1200 |
| `respect_robots` | boolean | true | see robots.txt below |

Unknown fields are rejected. Every problem is returned at once: `422 {"error":{"code":"invalid_job","fields":[{"field","message"}]}}`.

Selectors: `h1.title` gives the trimmed, whitespace-collapsed text of the first match; `a.next@href` gives
an attribute (`href` and `src` are resolved to absolute URLs). No match gives `null`.

Example (the A6 job, `fixtures/a6-job.json`):

```json
{
  "start_urls": ["https://FIXTURE_HOST/"],
  "max_pages": 20,
  "extract": { "name": "h1.product-name", "sku": ".sku", "price": ".price", "category": ".category", "description": ".description" }
}
```

## API

| method | path | result |
|---|---|---|
| POST | `/api/v1/jobs` | 201 `{run}`, `Location: /api/v1/runs/<id>` |
| GET | `/api/v1/runs?limit&offset` | runs, newest first |
| GET | `/api/v1/runs/<id>` | status (`queued`, `running`, `succeeded`, `failed`, `cancelled`), `pages {ok, failed, skipped}`, error, spec |
| GET | `/api/v1/runs/<id>/items?limit&after` | items with `next` cursor |
| GET | `/api/v1/runs/<id>/events?limit` | failed and skipped URLs with reasons (first 500 per run are kept) |
| GET | `/api/v1/runs/<id>/export.json` | JSON array of `{url, <fields in job order>}` |
| GET | `/api/v1/runs/<id>/export.csv` | CSV with header `url,<fields>`; add `?escape_formulas=false` for raw values |
| POST | `/api/v1/runs/<id>/cancel` | 202; queued runs are cancelled, running runs stop after in-flight pages |
| DELETE | `/api/v1/runs/<id>` | 204 for finished runs, 409 for active ones |
| GET | `/api/v1/capabilities` | `{crawlers: [...]}` |
| GET | `/healthz` | 200 when Postgres answers |

CSV follows RFC 4180: CRLF rows, fields with commas, quotes, CR or LF are quoted and quotes are doubled. By
default a cell starting with `=`, `+`, `-`, `@`, tab or CR gets a leading `'` so spreadsheets do not run
scraped text as a formula (OWASP CSV injection). Exports stream from Postgres page by page.

The UI at `/` has a job form, the run list, and a run page with items, events, export links and stop or
delete buttons. It uses no JavaScript, is served with a CSP that forbids scripts and framing, and renders all
scraped text escaped. State-changing requests that a browser marks cross-site, or whose `Origin` is not this
host, are refused, because the gate's basic auth credentials travel with cross-site requests.

## robots.txt

On by default, product token `SealedScraper`, fetched through sealed-egress once per origin per run, with
RFC 9309 failure handling (Crawlee 3.18.2 itself bypasses the proxy, skips TLS checks and allows everything on
errors, so the runner overrides it):

| robots.txt response | result |
|---|---|
| 2xx | rules apply (first 500 KiB) |
| 4xx, or more than 5 redirects | treated as unavailable: everything allowed |
| 5xx, network error, timeout, destination blocked by egress | treated as unreachable: everything disallowed |

Disallowed URLs are recorded as skipped (`robotsTxt`) and never fetched.

## Crawling behaviour

- One Crawlee `Configuration` per run with a non-persistent `MemoryStorage`; `CRAWLEE_PERSIST_STORAGE=false`
  is forced at start. Results go straight to Postgres.
- TLS certificates are always verified (`ignoreSslErrors: false`).
- An honest bot: `User-Agent: SealedScraper/1.0 (+https://github.com/sealed-dev/sealed/tree/main/catalog/apps/scraper)`,
  no generated browser headers, no fingerprinting, no retries to get around 401, 403 or 429.
- A final status of 400 or more is a failed page (4xx without retries). Non-HTML responses are failed pages.
- Firefox only (D-022). Preferences send loopback through the proxy too, turn off DNS-over-HTTPS, prefetching,
  WebRTC, Safe Browsing and other background traffic, and refuse downloads. The content sandbox keeps its
  default level, and the runner strips `MOZ_DISABLE_*_SANDBOX` and `CRAWLEE_DISABLE_BROWSER_SANDBOX`.
- At most `SCRAPER_MAX_RUNS` (default 2) runs crawl at once; the rest wait in order. After a restart, runs
  that were running are marked failed and queued runs start again.

## Images

| image | Dockerfile | contents |
|---|---|---|
| `scraper-runner-playwright` (shipped) | `images/scraper-runner-playwright/Dockerfile` | `mcr.microsoft.com/playwright:v1.62.1-noble` by digest, flattened with only Firefox kept (Chromium, WebKit and ffmpeg removed), tini, user `pwuser` |
| `scraper-runner` (Cheerio only) | `images/scraper-runner/Dockerfile` | `node:24.22.1-bookworm-slim` by digest, no Playwright packages, tini, user `node` |

Both build from the repository root, for example
`docker build -f catalog/apps/scraper/images/scraper-runner-playwright/Dockerfile .`, using the runner's own
`pnpm-lock.yaml`. Run with a read-only root filesystem and a tmpfs on `/tmp` (the fragment does this).

## Fixture site (acceptance test A6)

`fixtures/site/` is a static site of 10 linked product pages with the same five fields, a `robots.txt` that
disallows `/private/`, and one link to another host. The platform VM serves it at the root of a host name.
Running `fixtures/a6-job.json` against it must give the 10 items in `fixtures/expected-items.json`, one
`robotsTxt` skip and no request to the other host. Several values contain commas and quotes, so the CSV
export also checks quoting.

## Configuration

| variable | default | meaning |
|---|---|---|
| `DATABASE_URL` | required | Postgres URL without a password |
| `SCRAPER_DB_PASSWORD` or `SCRAPER_DB_PASSWORD_FILE` | none | database password |
| `HTTP_PROXY` (or `SCRAPER_PROXY_URL`) | required | sealed-egress; `SCRAPER_ALLOW_NO_PROXY=1` only for local development |
| `SEALED_AGENT_URL` | `http://sealed-agent:7070` | usage events; `SCRAPER_METERING=off` for local development |
| `SCRAPER_METER_FLUSH_MS`, `SCRAPER_METER_MAX_BATCH` | 5000, 50 | metering batches |
| `SCRAPER_MAX_RUNS` | 2 | concurrent runs (1 to 8) |
| `SCRAPER_CRAWLERS` | all installed | restrict crawlers, for example `cheerio` |
| `CRAWLEE_MEMORY_MBYTES` | 2048 | Crawlee autoscaling memory budget |
| `PORT`, `HOST`, `LOG_LEVEL` | 8080, 0.0.0.0, info | server |

## Development

```sh
cd catalog/apps/scraper/runner
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 pnpm install --ignore-workspace
pnpm typecheck && pnpm test          # unit, Cheerio crawl and Postgres tests
pnpm exec playwright install firefox && pnpm test:playwright   # browser crawl (CI)
```

The Postgres tests start a throwaway PostgreSQL 17 cluster under the repository's `tmp/` (set `PG_BIN` if the
binaries are not on the usual paths, or `SCRAPER_SKIP_PG=1` to skip them). Crawl tests serve the fixture site
locally behind a small stand-in for sealed-egress that resolves `fixture.test` itself, so a page that arrives
proves the request went through the proxy.
