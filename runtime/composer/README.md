# runtime/composer

The deterministic stack composer. Given a public deployment config and the release bundles it names, it produces `app-compose.json` for dstack, whose sha256 is the `stackHash` that the customer's wallet approves, the key broker recomputes and `sealed verify` checks. One Go implementation is shared by the key broker, the CLI and sealed-verifierd (D-006). The contract lives in `docs/INTERFACES.md` sections 1, 2, 5, 6, 7, 12, 14 and 15; this file documents the implementation and the details the contract leaves open.

## Packages

| package | path | purpose |
|---|---|---|
| `composer` | `runtime/composer` | config, manifest, egress and fragment parsing; bundle build and load; ids and hashes; `Compose` |
| `cjson` | `runtime/composer/cjson` | canonical JSON encoder and strict re-canonicalizer |
| `lint` | `runtime/composer/lint` | catalog lint (licenses, digests, telemetry, egress, exclusions, secrets, SBOMs) |
| `caddy` | `runtime/caddy` | Caddyfile template, payment-needed page |
| `envexec` | `runtime/envexec` | static entrypoint wrapper used by every app container |
| `schema` | `catalog/schema` | embedded `manifest.schema.json` |
| debug CLI | `runtime/composer/cmd/sealed-compose` | `bundle`, `lint`, `compose` for humans |

## API

```go
cfg, err := composer.ParseConfig(rawJSON)          // strict, normalized sealed-config/v1
b, err := composer.LoadBundle(tarBytes)            // canonical bundle, every hash computed
b, err := composer.BuildBundle(composer.BuildInput{AppDir: "catalog/apps/crm", Registry: defaults.Catalog.Registry})
res, err := composer.Compose(cfg, []*composer.Bundle{b1, b2})

res.AppCompose        // exact app-compose.json bytes
res.StackHash         // sha256(AppCompose)
res.ConfigHash        // sha256(CJSON(normalized config)) == sha256(res.ConfigJSON)
res.DeploymentID      // keccak256(abi.encode(customer, stackHash, salt))
res.ComposeJSON       // docker compose document (CJSON), the docker_compose_file value
res.EgressConfig      // sealed-egress config (section 12)
res.Caddyfile, res.CaddyfilePaymentNeeded
res.StackInfo         // sealed-stack/v1 for sealed-agent (below)
res.PreLaunchScript   // host rules (section 15)
res.Unbuilt           // images still at the all-zero digest; such a stack cannot boot

b.Hash, b.EgressPolicyHash, b.SBOMHash, b.AppID, b.ReleaseID, b.Info()   // publishRelease arguments
composer.AppID(slug), ReleaseID(appId, version, bundleHash), DeploymentID(customer, stackHash, salt),
composer.ImageID(name, version, measurementsHash), MeasurementsHash(mrtd, rtmr0, rtmr1, rtmr2)
cjson.Canonicalize(raw), cjson.Marshal(v), cjson.Parse(raw), cjson.Encode(tree)
lint.LintApp(dir, opts), lint.LintBundle(b, opts), lint.LintCatalog(root, opts), lint.EvaluateLicense(expr)
```

All hashes are `composer.Hash` (32 bytes, `Hex()` gives `0x` lowercase). Errors are typed where callers need the location: `*FragmentError{App, Service, Key}`, `*ManifestError{App, Field}`, `*cjson.Error{Kind}`.

## Inputs

### Public config (`sealed-config/v1`)

`ParseConfig` rejects unknown fields (keys must match exactly, case included), duplicate keys, floats, mixed-case hex, unsorted or duplicate `apps`, a `composerVersion` other than `composer.Version`, egress additions for apps not in the stack, invalid `host:port` entries, non-private or overlapping `allowedVpcRanges`, endpoint URLs with credentials, and unknown hostname schemes. Absent `egressAdditions` and `allowedVpcRanges` normalize to `{}` and `[]`; `configHash` is over the normalized form (`Config.CanonicalJSON`). `relayOwner`, `endpoints.relay` and `endpoints.relayAttest` are optional unless `llm-gateway` is in the stack.

Hostnames: `sslip` gives `<route>.<ip-with-dashes>.sslip.io`; `custom` needs a domain for every route in the stack plus `attest`, and no domains for routes outside it.

### Release bundle (section 7)

Layout, exactly: `manifest.yaml`, `compose.fragment.yaml`, `egress.yaml`, `LICENSES/**` (the app directory's `LICENSE-NOTICE` plus everything under its `LICENSES/`), `sbom/<image>.spdx.json`, `scan/<image>.json`. Any other file is rejected.

The tar is written by our own ustar encoder (not `archive/tar`) so its bytes cannot change with a Go release: entries sorted by path, explicit parent directory entries, mtime 0, uid/gid 0, empty uname/gname, mode 0644 files and 0755 directories, octal fields NUL-terminated, checksum `%06o\0 `, two zero blocks at the end and no record padding. Text files (valid UTF-8 without NUL) are LF-normalized. `LoadBundle` accepts only this canonical form (re-encoding the parsed files must give the input bytes), so one `bundleHash` names exactly one content.

At build time every `images[].ref` in the bundled `manifest.yaml` is set to `<catalog.registry>/<name>@<digest>` (edited on the YAML node tree, so comments survive). Bundles must carry refs; catalog sources must not need them. The composer never reads `config/defaults.yaml`, so a stack depends only on the config, the bundles and the composer version.

| hash | formula |
|---|---|
| bundleHash | `sha256(bundle.tar)` |
| egressPolicyHash | `sha256(CJSON(egress.yaml parsed))` |
| sbomHash | `sha256(CJSON({"<image name>": "0x<sha256 of sbom/<image>.spdx.json>"}))`, values `0x`-prefixed lowercase hex; `{}` when there are no SBOMs |
| releaseId | `keccak256(abi.encode(appId, version, bundleHash))` where `version` is the manifest's `release_version`, else `upstream.version` |

### Manifest

Validated against `catalog/schema/manifest.schema.json` (santhosh-tekuri/jsonschema v6, formats asserted), then: reserved ids (`sealed`, `sealed-*`, `caddy`, `gate`, `localhost`), `primary_service`, `routes[].service`, `healthcheck.service` and `bootstrap.service` prefixed with `<id>-`, unique images, routes and secrets, `path_or_host` equal to the route name or a path, `GATE_PASSWORD_BCRYPT` reserved, `tokens` and `pages` metering need `source: callback`, `telemetry_off_env` names valid and not composer-owned. Two schema additions, both optional: `release_version` and `images[].ref` (written only by the bundle builder).

### Fragment rules (section 14)

- Top level: `services`, `volumes` and `x-*` anchor blocks only.
- Service names: lowercase DNS labels starting with `<appId>-`, unique across the stack together with app aliases and sidecar names.
- Allowed keys: `image`, `command`, `entrypoint`, `environment`, `healthcheck`, `depends_on`, `volumes`, `tmpfs`, `user`, `working_dir`, `read_only`, `stop_grace_period`, `shm_size`, `ulimits`, `mem_limit`, `cpus`, `labels`, `x-sealed-secrets`. Anything else fails with `fragment: app "<id>" service "<svc>" key "<key>": not allowed in app fragments`.
- `image` must be `{{image:<name>}}` naming a manifest image; tags and literal references are rejected.
- `entrypoint` is required on every service, as a list of strings, because every service runs through envexec and setting an entrypoint clears the image's CMD. Declare `command` too if the image relies on it.
- `environment` holds public values only: map or `KEY=value` list, scalar values, no host passthrough (`KEY` without a value), no composer-owned keys (proxy variables, `NODE_USE_ENV_PROXY`), no declared secret names.
- Compose interpolation is never performed: `$$` means a literal `$`, a lone `$` stays literal, and `$NAME` or `${...}` is an error (it would read unmeasured host environment). The composer writes every `$` back as `$$`, so docker compose reproduces the literal, measured text. Manifest values are literal as written.
- `volumes`: named volumes declared in the fragment's top-level `volumes` (no options), as `name:/path[:ro]` or `{type: volume, source, target, read_only}`, or `{type: tmpfs, target, tmpfs: {size}}`. Bind mounts, anonymous volumes, reserved targets (`/run/sealed/...`, `/sealed/...`, the dstack socket) and duplicate targets are rejected.
- `depends_on`: services of the same app, no cycles; `service_healthy` needs a healthcheck on the target (from the fragment, or generated for the manifest's healthcheck service).
- `cpus` must be an integer or a quoted decimal: floats are not allowed anywhere in hashed documents.

## The composed stack

Project name `sealed`. Networks: `apps` (internal, `172.30.0.0/24`, bridge `sealed-apps`) and `edge` (`172.31.0.0/24`, bridge `sealed-edge`, inter-container traffic off), IPv6 off.

| service | apps IP | other | notes |
|---|---|---|---|
| `sealed-init` | none | `network_mode: none` | `/envexec install /sealed/bin`, exits; everything that uses envexec waits for `service_completed_successfully` |
| `sealed-egress` | `.2` | edge `.2` | config at `/etc/sealed/egress.json` (`SEALED_EGRESS_CONFIG`); healthcheck `tcp://127.0.0.1:3128` |
| `sealed-agent` | `.3` | port 7070 | only service with `/var/run/dstack.sock`, `/mnt/sealed-data` (bind, `rshared`), the data disk device and `SYS_ADMIN`; healthcheck `GET /v1/ready` |
| `caddy` | `.4` | edge `.4`, publishes 80/443 tcp | envexec with `--app _gate --secret GATE_PASSWORD_BCRYPT`; `/data` on the encrypted disk |
| `sealed-mpp-payer` | `.5` | port 8090 | only with `llm-gateway`; its key tmpfs is mounted only here (and in the agent) |
| `sealed-verifierd` | `.6` | port 8088 | only with `llm-gateway` |
| app primaries | `.16`, `.17`, ... | alias `<appId>` | in config app order |
| other app services | after the primaries | | app order, then name order |

Every app service gets: the envexec entrypoint `["/sealed/bin/envexec","--app","<appId>",("--secret"|"--optional-secret",NAME)...,"--",<entrypoint>...]`, `dns: [172.30.0.2]`, `HTTP_PROXY`/`HTTPS_PROXY`/`http_proxy`/`https_proxy=http://172.30.0.2:3128`, `NO_PROXY`/`no_proxy` (every service name and app alias in the stack plus `localhost,127.0.0.1`, sorted), `NODE_USE_ENV_PROXY=1`, the manifest's `telemetry_off_env`, read-only `sealed-bin` at `/sealed/bin` and `sealed-ready` at `/run/sealed/ready`, its app's secrets tmpfs at `/run/sealed/secrets/<appId>` (only on services that declare `x-sealed-secrets`), app volumes as binds of `/mnt/sealed-data/<appId>/<volume>`, `restart: unless-stopped` (`on-failure` for the manifest's bootstrap service), `logging: {driver: none}`, and `depends_on` on `sealed-agent` (healthy) and `sealed-init` (completed). The manifest healthcheck service gets `envexec probe http://127.0.0.1:<port><path>` unless the fragment defines its own healthcheck. Sidecar images come from `runtime-images.json` (`<registry>/<name>@<digest>`; zero digests carry `"unbuilt": true` and show up in `Result.Unbuilt`).

Measured inline configs (`configs.<name>.content`):

| config | content | mounted at |
|---|---|---|
| `sealed-config` | CJSON public config | `/etc/sealed/config.json` (agent, payer, verifierd) |
| `sealed-stack` | `sealed-stack/v1` | `/etc/sealed/stack.json` (agent) |
| `sealed-egress` | egress config | `/etc/sealed/egress.json` (egress) |
| `sealed-caddyfile` | Caddyfile | `/etc/caddy/Caddyfile` (caddy), `/etc/sealed/caddy/Caddyfile` (agent) |
| `sealed-caddyfile-payment-needed` | payment-needed variant | `/etc/sealed/caddy/Caddyfile.payment-needed` (agent) |
| `sealed-payment-page` | `runtime/caddy/payment-needed.html` | `/srv/sealed/payment-needed.html` (caddy) |

Docker volumes (sidecar plumbing only; app data never uses Docker volumes): `sealed-bin` (envexec), and tmpfs volumes `sealed-ready`, `sealed-caddy-admin`, `sealed-secrets-<appId>` for apps with secrets, `sealed-secrets-_gate`, and `sealed-secrets-sealed-mpp-payer` when the payer runs.

### Contract for the sidecars

- sealed-agent writes each secret to `/run/sealed/secrets/<appId>/<NAME>` (exact bytes, mode 0444; the directories are tmpfs with mode 0755 so non-root app users can read), the gate hash to `/run/sealed/secrets/_gate/GATE_PASSWORD_BCRYPT`, the payer files of section 15 to `/run/sealed/secrets/sealed-mpp-payer/`, then creates `/run/sealed/ready/ok` (write a temp file and rename). `GET /v1/ready` must return 2xx only after that. Env: `SEALED_CONFIG_FILE`, `SEALED_STACK_FILE`, `SEALED_CADDYFILE`, `SEALED_CADDYFILE_PAYMENT_NEEDED`, `SEALED_CADDY_ADMIN_SOCKET`, `SEALED_SECRETS_DIR`, `SEALED_READY_DIR`, `SEALED_DATA_DIR`, `SEALED_DATA_DEVICE` (`/dev/sealed-data`, mapped from `/dev/disk/by-id/google-sealed-data`; `/dev/mapper/control` is also mapped), `SEALED_EGRESS_STATS_URL`, `DSTACK_SOCKET`, `PORT`.
- Payment-needed switch: `POST /load` with `Content-Type: text/caddyfile` and the bytes of `/etc/sealed/caddy/Caddyfile.payment-needed`, over the unix socket `/run/sealed/caddy-admin/admin.sock`; restore by loading `/etc/sealed/caddy/Caddyfile`. Both files are measured, so the agent switches only between approved configs.
- `sealed-stack/v1` gives the agent what it cannot read from the config: per app `id`, `appId`, `releaseId`, `version`, `primaryService`, `services[{name, ip, primary}]`, `secrets[{name, optional}]`, `metering`, `healthcheck{service, port, path}`, `routes[{name, host, path, service, port, auth}]`, optional `bootstrap`; plus `sidecars`, `attestHost`, `gate` and `caddy` paths.
- sealed-egress reads `SEALED_EGRESS_CONFIG` (`/etc/sealed/egress.json`).

### Egress config (section 12)

Callers, sorted by IP: `sealed-agent` gets the key broker, platform API and Tempo RPC hosts; `caddy` gets `acme-v02.api.letsencrypt.org:443`; `sealed-mpp-payer` the relay and Tempo RPC; `sealed-verifierd` `api.trustedservices.intel.com:443`, `certificates.trustedservices.intel.com:443`, Tempo RPC and the relay attest host; every app service its app's `default_allow` plus the config's `egressAdditions` (an error if the app sets `customer_additions_allowed: false`). URL hosts become `host:port` with 443 or 80 by scheme. `listen` is `:3128`, `:53`, `:9100`; `upstreamDns` `8.8.8.8:53`, `8.8.4.4:53`; `allowedPrivateCidrs` is the config's `allowedVpcRanges`; `statsReaders` is the agent.

### Caddy

One site per route hostname plus `attest`. Routes on a host are ordered longest path first; a path route matches `/p` and `/p/*`. Auth modes: `gate` puts `basic_auth` (user `sealed`, bcrypt hash from `{env.GATE_PASSWORD_BCRYPT}`) in front and strips `Authorization` before proxying; `bearer-passthrough` sends requests with `Authorization: Bearer ...` straight to the app and gates the rest; `public` proxies without a gate. `attest` is public and maps `/` and `/attest` to `sealed-agent:7070/attest` keeping the query. Global options: admin on the unix socket, `persist_config off`, `ocsp_stapling off`, HTTP/1.1 and HTTP/2 only. Upstreams use `network_proxy none` (and are in `NO_PROXY`); ACME goes through the egress proxy via `HTTPS_PROXY`. The payment-needed variant serves the static page with status 402 on every app host, a plain-text 402 to bearer API calls, and leaves attest unchanged. Note for app packagers: browsers send gate credentials only when the page itself does not set `Authorization`; apps whose web UI sends its own bearer tokens should use `bearer-passthrough`.

### Host rules (section 15)

`pre_launch_script` rebuilds the `SEALED-EDGE` chain on every boot (ESTABLISHED,RELATED return, source `172.31.0.2` return, destination inside the edge subnet return, everything else drop) and inserts `-s 172.31.0.0/24 -j SEALED-EDGE` at the top of `DOCKER-USER` once. Only the subnet and IP vary.

### app-compose.json (section 6)

Exactly `allowed_envs`, `docker_compose_file`, `gateway_enabled`, `key_provider` (`tpm`), `key_provider_id`, `kms_enabled`, `local_key_provider_enabled`, `manifest_version` (2), `name` (`sealed-<first 8 hex of configHash>`), `no_instance_id`, `pre_launch_script`, `public_logs`, `public_sysinfo`, `public_tcbinfo` (true), `runner`, `secure_time`, `storage_fs` (`ext4`), as CJSON with no trailing newline.

## Determinism and versioning

Every output is built from sorted inputs and serialized as CJSON or rendered from fixed templates; map iteration order never reaches the output. `composer.Version` (`1.0.0`) must equal `config.composerVersion`. Any change to composed bytes (this code, `runtime-images.json`, the Caddy template, the host rules) needs a new version, because approved stacks pin the old bytes. `testdata/golden/` pins the fixture stack's outputs: when it fails on purpose, bump `Version`, then `go test ./runtime/composer -run Golden -update`. The golden files double as cross-implementation vectors.

## Lint

`lint.LintApp` (catalog source), `lint.LintBundle` (release bundle, also checks refs are under `ghcr.io/` and SBOMs are present) and `lint.LintCatalog` (all apps, id matches directory, shared route names). Errors block a release; warnings need review. License policy: rule 9 plus the D-021 additions (PostgreSQL, Zlib, 0BSD, Unlicense, CC0-1.0, PSF-2.0, Python-2.0, BSL-1.0); GPL-2.0-or-later counts as allowed (usable under GPL-3.0); GPL-2.0-only and other OSI licenses common in distributions are accepted only for OS packages (purl `pkg:deb`, `pkg:apk`, `pkg:rpm`, `pkg:alpm`). Expressions are evaluated with SPDX semantics: `OR` takes the best alternative (a banned alternative yields a warning to record the election), `AND` the worst, `WITH Commons-Clause` is banned. Hard fails: SSPL, BUSL, FSL, Elastic, Sustainable Use, Commons Clause, RSAL, proprietary and enterprise LicenseRefs. Other checks: zero digests (`unbuilt-image`), image sources with tags, unused images, empty `telemetry_off_env`, egress notes, `license_exclusions` for open-core upstreams (LiteLLM, Twenty, Appsmith, OpenHands), unused secrets, literal secret-like env values, SBOM package licenses and packages matching `license_exclusions` or `litellm_enterprise`, `enterprise/`, `@anthropic-ai/claude-agent-sdk`.

## CLI

```sh
go run ./runtime/composer/cmd/sealed-compose bundle --app-dir catalog/apps/crm --out crm.tar
go run ./runtime/composer/cmd/sealed-compose lint --catalog catalog/apps --require-sbom
go run ./runtime/composer/cmd/sealed-compose compose --config stack.json --app-dir catalog/apps/crm --print summary
go run ./runtime/composer/cmd/sealed-compose compose --config runtime/composer/testdata/config.json \
  --app-dir runtime/composer/testdata/apps/notes --app-dir runtime/composer/testdata/apps/llm-gateway \
  --fill-release-ids --out /tmp/stack
```

`--print` selects `summary`, `app-compose`, `compose`, `egress`, `caddyfile`, `caddyfile-payment`, `stack`, `config` or `pre-launch`. `--fill-release-ids` is for local experiments only.

## Tests

```sh
go test ./runtime/... ./catalog/...
go test ./runtime/composer/cjson -run '^$' -fuzz FuzzCanonicalize -fuzztime 30s
SEALED_CADDY_BIN=/path/to/caddy go test ./runtime/composer -run RealCaddy -v   # optional, Caddy 2.11.x
```

Covered: the shared CJSON vectors including error cases; the dstack golden vectors of `testdata/dstack/vectors.py` (compose sha256 `a06cf477...`, RTMR3 `30498094...`, PCR14) computed in Go; Solidity ABI id formulas against values from `cast`; byte-identical bundles across runs, mtimes and permissions; canonical-only bundle loading; determinism of `Compose` across runs and input orders; every single-byte change of a fragment, an egress policy or the config changes `stackHash`; every forbidden fragment key and mount; `docker compose config --quiet` on the composed document (needs only the docker CLI); a real Caddy run of the gate, bearer, attest and payment switch when `SEALED_CADDY_BIN` is set; the lint rules. Fixture apps live in `testdata/apps` (`notes`, a fake `llm-gateway`).
