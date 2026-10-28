# runtime/composer

The deterministic stack composer, version `1.2.0`. Given a public deployment config and the release bundles it names, it produces `app-compose.json` for dstack, whose sha256 is the `stackHash` that the customer's wallet approves, the key broker recomputes and `sealed verify` checks. One Go implementation is shared by the key broker, the CLI and sealed-verifierd (D-006).

This file is the authoritative contract for app fragments and for the composed stack: what a catalog package may declare, what the composer adds, and what the sidecars (sealed-agent, sealed-egress, Caddy, sealed-mpp-payer) can rely on. `docs/INTERFACES.md` sections 1, 2, 5, 6, 7, 12, 14 and 15 describe the same contract at a higher level; where they differ, this file and the integration brief (D-040 to D-050) win, and the differences are listed at the end for the owner of INTERFACES.

## Packages

| package | path | purpose |
|---|---|---|
| `composer` | `runtime/composer` | config, manifest, egress and fragment parsing; bundle build and load; ids and hashes; `Compose`; release asset URLs and bundle fetch; secret generators |
| `cjson` | `runtime/composer/cjson` | canonical JSON encoder and strict re-canonicalizer, the only CJSON implementation in Go (egress uses it too) |
| `lint` | `runtime/composer/lint` | catalog lint (licenses, digests, telemetry, egress, exclusions, exceptions, secrets, SBOMs, waivers) |
| `caddy` | `runtime/caddy` | Caddyfile template (forward_auth gate), payment-needed page |
| `envexec` | `runtime/envexec` | static entrypoint wrapper used by every app container |
| `schema` | `catalog/schema` | embedded `manifest.schema.json` |
| debug CLI | `runtime/composer/cmd/sealed-compose` | `bundle`, `lint`, `compose`, `version` |
| catalog tooling | `catalog/tools` | Node and Python wrappers around `sealed-compose lint` for app test suites |

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
res.RequireBuilt()    // error when Unbuilt is not empty; release and approval flows call it

b.Hash, b.EgressPolicyHash, b.SBOMHash, b.AppID, b.ReleaseID, b.Info()   // publishRelease arguments
composer.AppID(slug), ReleaseID(appId, version, bundleHash), DeploymentID(customer, stackHash, salt),
composer.ImageID(name, version, measurementsHash), MeasurementsHash(mrtd, rtmr0, rtmr1, rtmr2)

a, err := composer.NewReleaseAssets(defaults.Catalog.ReleaseAssetBase, "crm", version)  // D-046 asset URLs
a, err := b.Assets(base)                           // same, for a loaded bundle
b, err := composer.FetchBundle(ctx, httpClient, a.Bundle, onchainBundleHash, composer.DirCache{Dir: dir})
v, err := composer.GenerateSecret("password", nil) // secret generators of the manifest schema

cjson.Canonicalize(raw), cjson.Marshal(v), cjson.Parse(raw), cjson.Encode(tree)
lint.LintApp(dir, opts), lint.LintBundle(b, opts), lint.LintCatalog(root, opts), lint.EvaluateLicense(expr)
```

All hashes are `composer.Hash` (32 bytes, `Hex()` gives `0x` lowercase). Errors are typed where callers need the location: `*FragmentError{App, Service, Key}`, `*ManifestError{App, Field}`, `*cjson.Error{Kind}`, `*BundleHashMismatchError{URL, Want, Got}`.

## Inputs

### Public config (`sealed-config/v1`)

`ParseConfig` rejects unknown fields (keys must match exactly, case included), duplicate keys, floats, mixed-case hex, unsorted or duplicate `apps`, a `composerVersion` other than `composer.Version`, egress additions for apps not in the stack, invalid `host:port` entries, non-private or overlapping `allowedVpcRanges` (the whole range must be RFC 1918 space and must not overlap `apps`, `edge` or any of the 16 app networks `172.30.1.0/24` to `172.30.16.0/24`), endpoint URLs with credentials, and unknown hostname schemes. Size bounds (configs reach the key broker and the preview API from untrusted callers): at most 128 KiB of JSON, 16 apps, 64 egress additions per app and 256 in total, 32 VPC ranges. `Compose` also refuses an `app-compose.json` over dstack's 50 MiB limit.

Normalization: absent `egressAdditions`, `allowedVpcRanges` and `debug` become `{}`, `[]` and `false`, and the canonical form always carries them; `configHash` is over the normalized form (`Config.CanonicalJSON`). A TypeScript twin must apply the same defaults before hashing.

- `debug` (boolean, default `false`): when true every container uses the `local` logging driver, otherwise `none`. It is part of configHash, so the customer approves it; verifiers should show it.
- `relayOwner`, `endpoints.relay` and `endpoints.relayAttest` are optional unless `llm-gateway` is in the stack. Then `endpoints.relay` must be exactly the origin of `endpoints.relayAttest` (scheme and host, no path or trailing slash), because the relay is served on its deployment's attest host (D-045) and the payer pins relay requests to the attested TLS key.

Hostnames: `sslip` gives `<route>.<ip-with-dashes>.sslip.io`; `custom` needs a domain for every route in the stack plus `attest`, no domain for routes outside it, and no domain for a route served on the attest host.

### Release bundle (section 7)

Layout, exactly: `manifest.yaml`, `compose.fragment.yaml`, `egress.yaml`, `LICENSES/**` (the app directory's `LICENSE-NOTICE` plus everything under its `LICENSES/`), `sbom/<image>.spdx.json`, `scan/<image>.json`. Any other file is rejected.

The tar is written by our own ustar encoder (not `archive/tar`) so its bytes cannot change with a Go release: entries sorted by path, explicit parent directory entries, mtime 0, uid/gid 0, empty uname/gname, mode 0644 files and 0755 directories, octal fields NUL-terminated, checksum `%06o\0 `, two zero blocks at the end and no record padding. Text files (valid UTF-8 without NUL) are LF-normalized. `LoadBundle` accepts only this canonical form (re-encoding the parsed files must give the input bytes), so one `bundleHash` names exactly one content. Bundles are at most 64 MiB.

At build time every `images[].ref` in the bundled `manifest.yaml` is set to `<catalog.registry>/<name>@<digest>` (edited on the YAML node tree, so comments survive). `Compose` requires each ref to be exactly `<registry>/<name>@<digest>` with the registry of `runtime-images.json` (image pulls do not go through sealed-egress, so VMs pull only from the catalog registry); `config/defaults.yaml` `catalog.registry` must name the same registry, which a test checks. The composer never reads `config/defaults.yaml`, so a stack depends only on the config, the bundles and the composer version.

| hash | formula |
|---|---|
| bundleHash | `sha256(bundle.tar)` |
| egressPolicyHash | `sha256(CJSON(egress.yaml parsed))` |
| sbomHash | `sha256(CJSON({"<image name>": "0x<sha256 of sbom/<image>.spdx.json>"}))`, values `0x`-prefixed lowercase hex; `{}` when there are no SBOMs |
| releaseId | `keccak256(abi.encode(appId, version, bundleHash))` where `version` is the manifest's `release_version`, else `upstream.version` |

### Release assets (D-046)

`NewReleaseAssets(base, appId, version)` applies the rule. `base` is `catalog.release_asset_base` (`https://github.com/sealedtempo/sealed/releases/download`), `appId` the slug and `version` the version hashed into releaseId, used literally (so `v2.52.0` gives the tag `crm-vv2.52.0`).

| asset | URL |
|---|---|
| bundle | `<base>/<appId>-v<version>/<appId>-<version>.bundle.tar` |
| cosign signature | the bundle URL plus `.sig` |
| cosign certificate | the bundle URL plus `.crt` |
| SLSA provenance | the bundle URL plus `.intoto.jsonl` |
| SBOM of an image | `<base>/<appId>-v<version>/sbom.<image>.spdx.json` (the bundle's `sbom/<image>.spdx.json`; GitHub asset names cannot contain `/`) |

The version must match `^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$`: GitHub renames asset names with other characters (a `+` build suffix included), which would publish the bundle at a URL nobody fetches. Lint reports such versions. `FetchBundle(ctx, client, url, bundleHash, cache)` downloads a bundle (redirects followed, at most 64 MiB), accepts it only when its sha256 equals the onchain bundleHash (else `*BundleHashMismatchError`, the key broker's `bundle_hash_mismatch`), loads it in canonical form and stores it in a content-addressed `BundleCache`; `DirCache` re-hashes every entry on read, so a corrupted file is a miss.

### Manifest

Validated against `catalog/schema/manifest.schema.json` (santhosh-tekuri/jsonschema v6, formats asserted), then:

- Reserved ids (`sealed`, `sealed-*`, `caddy`, `gate`, `localhost`); `primary_service`, `routes[].service`, `healthcheck.service` and `bootstrap.service` prefixed with `<id>-`; unique images, routes and secrets; `GATE_PASSWORD_BCRYPT` reserved; `tokens` and `pages` metering need `source: callback`; `telemetry_off_env` names valid and not composer-owned.
- Routes: `routes[].service` must be the `primary_service`, because Caddy is on the shared `apps` network only (D-041). `path_or_host` is the route name or a path. `auth` must be `gate`, except `llm-gateway` route `gateway` (`bearer-passthrough`, LiteLLM keys) and `inference-relay` route `relay` (`public`, paid MPP endpoint); anything else is a manifest error, so a manifest cannot switch the gate off. `on_attest_host: true` is allowed only for the route named `relay`, which then needs a path prefix (for example `/v1`) that is not `/attest`; Caddy serves it on the attest host, with the same origin and TLS certificate as `/attest` (D-045), and the route gets no host of its own.
- Secrets: `name`, `description`, `generate`, optional `optional` and `same_as`. Generators: `none`, `hex32` (32 random bytes as 64 lowercase hex characters), `base64-32` (32 random bytes, standard base64 with padding), `sk-hex32` (`sk-` plus hex32) and `password` (24 characters drawn uniformly from `[A-Za-z0-9]`); `GenerateSecret` implements them. `same_as: "<appId>/<NAME>"` (D-043) makes the secret the value of another app's secret: it needs `generate: none` and may not name its own app. `Compose` requires the referenced app to be in the stack and to declare that secret, which may not itself be a reference, and a required secret may not reference an optional one. The key broker returns the referenced value under the referencing app's name, and `sealed secrets` never asks for it twice. `LintCatalog` checks the same rules across the catalog.
- `bootstrap`: optional `service` and `done_file`. The bootstrap service gets `restart: on-failure`. `done_file` is `<volume>/<path>` relative to `/mnt/sealed-data/<appId>/`, a clean path without `.` or `..` segments: sealed-agent keeps the app's routes closed (503 from the gate) until it exists (D-044). The older form, an absolute path in `bootstrap.service` under one of its named-volume mounts, still resolves to the same data-disk path and lint warns; a path on a tmpfs is rejected, since the agent cannot see it.
- `license_exceptions: [{decision, paths, reason}]`: see Lint.
- Optional fields: `release_version`, `images[].ref` (written only by the bundle builder), `telemetry_none_reason`, `routes[].on_attest_host`, `secrets[].same_as`, `license_exceptions`, `bootstrap`, `notes`.

### Fragment rules

- Top level: `services`, `volumes` and `x-*` anchor blocks only.
- Service names: lowercase DNS labels starting with `<appId>-`, at most 57 characters, without `--` (egress caller names are derived from them), unique across the stack together with app aliases and sidecar names.
- Allowed service keys: `image`, `command`, `entrypoint`, `environment`, `healthcheck`, `depends_on`, `volumes`, `tmpfs`, `user`, `working_dir`, `read_only`, `stop_grace_period`, `shm_size`, `ulimits`, `mem_limit`, `cpus`, `labels`, `x-sealed-secrets`. Anything else fails with `fragment: app "<id>" service "<svc>" key "<key>": not allowed in app fragments` (so no `privileged`, `cap_add`, `devices`, `network_mode`, `networks`, `ports`, `pid`, `ipc`, `security_opt`, `build`, `env_file`, `secrets`, `configs`, `extra_hosts`, `dns` or bind mounts).
- `image` must be `{{image:<name>}}` naming a manifest image; tags and literal references are rejected.
- `entrypoint` is required on every service, as a list of strings, because every service runs through envexec and setting an entrypoint clears the image's CMD. Declare `command` too if the image relies on it.
- `environment` holds public values only: map or `KEY=value` list, scalar values, no host passthrough (`KEY` without a value), no composer-owned keys (proxy variables, `NODE_USE_ENV_PROXY`, `SEALED_PUBLIC_URL_*`), no declared secret names.
- `x-sealed-secrets`: names from the manifest's `secrets`. The service gets exactly those files (below).
- Compose interpolation is never performed: `$$` means a literal `$`, a lone `$` stays literal, and `$NAME` or `${...}` is an error (it would read unmeasured host environment). The composer writes every `$` back as `$$`, so docker compose reproduces the literal, measured text. Manifest values are literal as written.
- Top-level `volumes`: names only, each empty or `{x-sealed-owner: "<uid>:<gid>"}` (decimal ids, at most 2^31-1). No driver or other options: every volume is a directory on the encrypted data disk. The owner is recorded in `sealed-stack/v1`, and the agent creates the directory with that owner before it opens the ready gate.
- Service `volumes`: declared named volumes as `name:/path[:ro]` or `{type: volume, source, target, read_only}`, or `{type: tmpfs, target, tmpfs: {size}}`. Bind mounts, anonymous volumes, reserved targets (`/run/sealed/...`, `/sealed/...`, the dstack socket) and duplicate targets are rejected.
- `tmpfs`: `<path>[:size=<n>[k|m|g],mode=<octal>]` with the same target rules (clean absolute path, not reserved, not also a volume target). Other options (`exec`, `suid`, `dev`, `uid`, ...) are rejected, so Docker's `noexec,nosuid,nodev` defaults stay.
- `depends_on`: services of the same app, no cycles; `service_healthy` needs a healthcheck on the target (from the fragment, or generated for the manifest's healthcheck service).
- `cpus` must be an integer or a quoted decimal: floats are not allowed anywhere in hashed documents.

## The composed stack

Project name `sealed`. Every network is a bridge with IPv6 off.

| network | subnet | bridge | members |
|---|---|---|---|
| `apps` | `172.30.0.0/24`, internal | `sealed-apps` | the sidecars and each app's primary service (alias `<appId>`) |
| `edge` | `172.31.0.0/24`, inter-container traffic off | `sealed-edge` | sealed-egress `.2`, Caddy `.4` (published 80 and 443) |
| `app-<appId>` | `172.30.<n>.0/24`, internal | `sealed-app<n>` | every service of the app, sealed-egress `.2`, sealed-agent `.3` |

`n` is the app's position in the config's sorted `apps` (1 to 16). Two containers can talk only if they share a network, so a service of one app can reach another app's service only when both are primaries on `apps` (for example coding-agent's primary to `llm-gateway`, llm-gateway's primary to `sealed-mpp-payer`). A non-primary service (a database, a worker, a bootstrap job) is reachable only from its own app and from sealed-egress and sealed-agent. Caddy, the payer and verifierd are on `apps` only.

| service | `apps` | app networks | notes |
|---|---|---|---|
| `sealed-init` | none | none | `network_mode: none`; `/envexec install /sealed/bin`, exits; everything that uses envexec waits for `service_completed_successfully` |
| `sealed-egress` | `.2` | `172.30.<n>.2` on each | edge `.2`; config at `/etc/sealed/egress.json` (`SEALED_EGRESS_CONFIG`); healthcheck `tcp://127.0.0.1:3128` |
| `sealed-agent` | `.3` | `172.30.<n>.3` on each | port 7070; the only service with `/var/run/dstack.sock`, `/mnt/sealed-data` (bind, `rshared`), the host secrets directory, the data disk device, `/dev/mapper/control`, `device_cgroup_rules` `b 252:* rwm`, `b 253:* rwm`, `b 254:* rwm` and `SYS_ADMIN`; healthcheck `GET /v1/ready` |
| `caddy` | `.4` | none | edge `.4`; `group_add: ["10001"]`; holds no secret; `/data` on the encrypted disk |
| `sealed-mpp-payer` | `.5` | none | port 8090; only with `llm-gateway` |
| `sealed-verifierd` | `.6` | none | port 8088; only with `llm-gateway`; `SEALED_VERIFIERD_LIVE_HOSTS` is the relay attest host, so live checks fetch nothing else |
| app primaries | `.16`, `.17`, ... in app order | `172.30.<n>.16` | alias `<appId>` on `apps` |
| other app services | none | `172.30.<n>.17`, ... in name order | |

Every service gets `security_opt: ["no-new-privileges:true"]` and drops capabilities, because `sealed-egress` identifies callers by source IP: `sealed-init`, `sealed-egress`, `sealed-mpp-payer` and `sealed-verifierd` drop `ALL`; `caddy` drops `ALL` and adds back `NET_BIND_SERVICE` (its binary carries that file capability); `sealed-agent` drops `NET_RAW` and adds `SYS_ADMIN` (it keeps `MKNOD` for libdevmapper); app services drop `AUDIT_WRITE`, `MKNOD`, `NET_RAW` and `SETFCAP` and keep the rest of Docker's default set that image entrypoints rely on (`CHOWN`, `SETUID`, `SETGID`, ...). Fragments cannot set `cap_*` or `security_opt`. `proxyAuth` stays off (identity by source IP, NET_RAW dropped, separate app networks).

Every app service of app `n` gets:

- the envexec entrypoint `["/sealed/bin/envexec","--app","<appId>",("--secret"|"--optional-secret",NAME)...,"--",<entrypoint>...]`;
- `dns: [172.30.<n>.2]` and `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` = `http://172.30.<n>.2:3128` (sealed-egress on its own app network); `NO_PROXY`/`no_proxy` (every service name and app alias in the stack plus `localhost,127.0.0.1`, sorted); `NODE_USE_ENV_PROXY=1`; the manifest's `telemetry_off_env`;
- `SEALED_PUBLIC_URL_<ROUTE>=https://<host>` for every route the app owns (route name upper-cased, `-` as `_`, no trailing slash; the attest host for a route on the attest host);
- read-only `sealed-bin` at `/sealed/bin` and `sealed-ready` at `/run/sealed/ready`;
- one read-only bind per secret it lists in `x-sealed-secrets` (below);
- app volumes as binds of `/mnt/sealed-data/<appId>/<volume>` with `create_host_path: false`;
- `restart: unless-stopped` (`on-failure` for the bootstrap service), `logging: {driver: none}` (`local` with `debug`), and `depends_on` on `sealed-agent` (healthy) and `sealed-init` (completed).

The manifest healthcheck service gets `envexec probe http://127.0.0.1:<port><path>` unless the fragment defines its own healthcheck. Sidecar images come from `runtime-images.json` (`<registry>/<name>@<digest>`; zero digests carry `"unbuilt": true` and show up in `Result.Unbuilt`).

### Secrets (D-042)

A service gets bind mounts of exactly the secret files it lists in `x-sealed-secrets`, never a directory: `{type: bind, source: /run/sealed/secrets/<appId>/<NAME>, target: the same path, read_only: true, bind: {create_host_path: false}}`. sealed-mpp-payer gets `/run/sealed/secrets/sealed-mpp-payer/ENCLAVE_KEY` and `SPEND_LIMIT_PER_DAY` the same way. The sources are files on the host's `/run` tmpfs (inside the CVM), written by sealed-agent through its bind of `/run/sealed/secrets` (the only secrets mount Docker may create). envexec exports only the declared names. Caddy needs no secret: the gate password hash stays in sealed-agent. No Docker volume holds secrets.

### Measured inline configs (`configs.<name>.content`)

| config | content | mounted at |
|---|---|---|
| `sealed-config` | CJSON public config | `/etc/sealed/config.json` (agent, payer, verifierd) |
| `sealed-stack` | `sealed-stack/v1` | `/etc/sealed/stack.json` (agent) |
| `sealed-egress` | egress config | `/etc/sealed/egress.json` (egress) |
| `sealed-caddyfile` | Caddyfile | `/etc/caddy/Caddyfile` (caddy), `/etc/sealed/caddy/Caddyfile` (agent) |
| `sealed-caddyfile-payment-needed` | payment-needed variant | `/etc/sealed/caddy/Caddyfile.payment-needed` (agent) |
| `sealed-payment-page` | `runtime/caddy/payment-needed.html` | `/srv/sealed/payment-needed.html` (caddy) |

Docker volumes (sidecar plumbing only): `sealed-bin` (envexec), and tmpfs volumes `sealed-ready` (mode 0755) and `sealed-caddy-admin` (`size=1m,mode=2770,uid=10001,gid=10001`). Data binds are never created by Docker (`create_host_path: false`, also for Caddy's `/mnt/sealed-data/_caddy/data`): after a reboot dockerd restarts containers without waiting for `depends_on`, and a container that started before sealed-agent opened the LUKS disk would otherwise bind a fresh directory on the host side of the mount point. With a missing source the container fails to start, and `docker compose up` starts it once the agent is healthy. Secret binds behave the same way before the agent has written the files.

### `sealed-stack/v1`

CJSON, measured, mounted at `/etc/sealed/stack.json` and read by the agent from the booted app-compose:

```
{ "schema": "sealed-stack/v1", "composerVersion": "1.2.0",
  "apps": [ {
      "id", "appId", "releaseId", "version", "primaryService",
      "network": { "name": "app-<id>", "subnet": "172.30.<n>.0/24", "egress": "172.30.<n>.2", "agent": "172.30.<n>.3" },
      "services": [ { "name", "ip" /* address on the app network */, "ips" /* every address, sorted */,
                      "networks": { "app-<id>": "...", "apps": "..." /* primary only */ }, "primary", "secrets": [NAME] } ],
      "secrets": [ { "name", "optional", "sameAs"? } ],
      "metering": { "unit", "source" },
      "healthcheck": { "service", "port", "path" },
      "routes": [ { "name", "host", "path", "service", "port", "auth", "onAttestHost", "publicUrl" } ],
      "volumes": [ { "name", "path", "owner"? /* "<uid>:<gid>" */ } ],
      "bootstrap"?: { "service", "doneFile", "donePath" /* data-disk path, "" only without a done file */ } } ],
  "dataRoot": "/mnt/sealed-data", "dataDirs": [sorted data bind sources, Caddy's included],
  "secretsRoot": "/run/sealed/secrets", "secretFiles": [sorted secret file binds, the payer's included],
  "sidecars": { "sealed-egress": "172.30.0.2", "sealed-agent": "172.30.0.3", "caddy": "172.30.0.4", ... },
  "attestHost",
  "gate": { "username": "sealed", "secretApp": "_gate", "secret": "GATE_PASSWORD_BCRYPT", "path": "/v1/gate", "cookie": "sealed_gate", "cookieMaxAgeSeconds": 43200 },
  "caddy": { "adminSocket": "/run/sealed/caddy-admin/admin.sock", "adminSocketMode": "0660", "adminSocketOwner": "10001:10001",
             "caddyfile": "/etc/sealed/caddy/Caddyfile", "caddyfilePaymentNeeded": "/etc/sealed/caddy/Caddyfile.payment-needed" } }
```

### Contract for the sidecars

sealed-agent:

- Env: `SEALED_CONFIG_FILE`, `SEALED_STACK_FILE`, `SEALED_CADDYFILE`, `SEALED_CADDYFILE_PAYMENT_NEEDED`, `SEALED_CADDY_ADMIN_SOCKET`, `SEALED_SECRETS_DIR` (`/run/sealed/secrets`), `SEALED_READY_DIR`, `SEALED_DATA_DIR`, `SEALED_DATA_DEVICE` (`/dev/sealed-data`, mapped from `/dev/disk/by-id/google-sealed-data`; `/dev/mapper/control` is also mapped and the dm majors 252 to 254 are allowed), `SEALED_EGRESS_STATS_URL`, `DSTACK_SOCKET`, `PORT`, plus the proxy variables for `172.30.0.2`.
- Before the ready gate: unlock the data disk, create every `dataDirs` entry (each app volume with its `owner`, else root), check that `secretsRoot` is on tmpfs, and write every `secretFiles` entry with its exact bytes, mode 0444 (directories 0755), an empty file for an optional secret the customer did not set (a missing bind source would stop the container) and the referenced value for a `sameAs` secret. Then create `/run/sealed/ready/ok` (temp file and rename). `GET /v1/ready` returns 2xx only after that. Files are written before the apps start and never replaced while they run (a rename would leave the running containers on the old inode).
- Gate (D-044): `GET /v1/gate?route=<route>` with the client's headers, plus `X-Forwarded-Method` and `X-Forwarded-Uri`, and no body. 200 for a valid `sealed_gate` cookie (route independent, HMAC-SHA256 with a per-boot key) or Basic auth as `sealed` matching the bcrypt hash `_gate/GATE_PASSWORD_BCRYPT` from the key broker; on a Basic success the 200 carries `Set-Cookie: sealed_gate=...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`, which Caddy copies to the client. 401 with `WWW-Authenticate: Basic realm="sealed"` otherwise. 503 `starting` until the bootstrap of the route's app is done, that is until its `bootstrap.donePath` exists or its bootstrap service has exited 0 (apps without a bootstrap are never held). Any non-2xx response reaches the client unchanged.
- Caddy admin: the socket `/run/sealed/caddy-admin/admin.sock` is created by Caddy with mode 0660 in the `sealed-caddy-admin` tmpfs (owner 10001:10001, setgid), so it belongs to group 10001 and the agent, after dropping to 10001:10001, connects without a root helper. Payment-needed switch: `POST /load` with `Content-Type: text/caddyfile` and the bytes of `/etc/sealed/caddy/Caddyfile.payment-needed`; restore by loading `/etc/sealed/caddy/Caddyfile`. Both are measured, so the agent switches only between approved configs.
- Callers: a service may reach the agent from any address in its `ips` (a primary resolves `sealed-agent` on either network), so caller checks (usage events, `/v1/spend`) use `ips`, and health probes use `ip`.

sealed-egress reads `SEALED_EGRESS_CONFIG` (`/etc/sealed/egress.json`), listens on every network it joins, and identifies callers by source address.

### Egress config (section 12)

One caller per source address, sorted by address. A caller is `{name, ip, allow}`; egress requires unique names and one address per caller, so:

| caller | name | address | allow |
|---|---|---|---|
| sealed-agent | `sealed-agent` and `sealed-agent--app-<appId>` | `172.30.0.3`, `172.30.<n>.3` | key broker, platform API, Tempo RPC |
| Caddy | `caddy` | `172.30.0.4` | `acme-v02.api.letsencrypt.org:443` |
| sealed-mpp-payer | `sealed-mpp-payer` | `172.30.0.5` | relay, Tempo RPC |
| sealed-verifierd | `sealed-verifierd` | `172.30.0.6` | `api.trustedservices.intel.com:443`, `certificates.trustedservices.intel.com:443`, Tempo RPC, relay attest host, and the release asset hosts `github.com:443`, `objects.githubusercontent.com:443` and `release-assets.githubusercontent.com:443` (bundles for `stack_recompute`, D-046, D-061) |
| app service | `<service>` | its app-network address | the app's `default_allow` plus the config's `egressAdditions` |
| app primary on `apps` | `<service>--apps` | its `apps` address | the same as the service |

`egressAdditions` for an app with `customer_additions_allowed: false` are an error. URL hosts become `host:port` with 443 or 80 by scheme. IPv4 literals in allow entries and endpoints must be public unicast: loopback, link-local (metadata), `0/8`, `100.64/10`, `192.0.0/24`, `192.88.99/24`, `198.18/15`, multicast, reserved and broadcast are rejected, and RFC 1918 literals are accepted only in `egressAdditions` inside the config's `allowedVpcRanges`. `default_allow` holds at most 256 entries. `listen` is `:3128`, `:53`, `:9100`; `upstreamDns` `8.8.8.8:53`, `8.8.4.4:53`; `allowedPrivateCidrs` is the config's `allowedVpcRanges`; `statsReaders` is `172.30.0.3`. The config is canonical CJSON, checked by egress with this package's `cjson`.

### Caddy

One site per route host, plus the attest site. Routes on a host are ordered longest path first; a path route matches `/p` and `/p/*`. Every app handle body is a `route` block, so directives run in the written order.

- `gate`: `request_header -X-Sealed-Gate-Set-Cookie` (a client cannot supply it), then `forward_auth sealed-agent:7070 { uri /v1/gate?route=<route>; copy_headers Set-Cookie>X-Sealed-Gate-Set-Cookie }`, then the copied `Set-Cookie` goes onto the client response and the relay header is removed, then `Authorization` is removed only when it carries Basic credentials for the user `sealed` (`^[Bb][Aa][Ss][Ii][Cc] +c2VhbGVkO`, base64 of `sealed:`), so an app's own `Authorization` (Twenty's Bearer token) passes through untouched. `basic_auth` is not used any more.
- `bearer-passthrough`: requests with `Authorization: Bearer ...` go straight to the app; the rest of the route is gated as above with the same route name.
- `public`: proxied without a gate.
- On every app request, the `sealed_gate` cookie is removed from the `Cookie` header (an emptied header is dropped), because the cookie is valid on every route and an app must not be able to replay it.
- The attest site maps `/` and `/attest` to `sealed-agent:7070/attest` keeping the query, serves the routes with `on_attest_host` (the relay's `/v1`) next to it, and answers 404 elsewhere.
- Global options: admin on `unix//run/sealed/caddy-admin/admin.sock|0660`, `persist_config off`, `ocsp_stapling off`, HTTP/1.1 and HTTP/2 only. Upstreams use `network_proxy none` (and are in `NO_PROXY`); ACME goes through the egress proxy via `HTTPS_PROXY`.
- Payment-needed variant: every app host serves the static page with status 402 (bearer API calls get a plain-text 402), routes on the attest host answer a plain-text 402, and `/attest` is unchanged.

The template is checked against a real Caddy v2.11.7 by `TestCaddyfileWithRealCaddy` (set `SEALED_CADDY_BIN`), with a fake agent implementing the gate contract above.

### Host rules (section 15)

`pre_launch_script` (host rules v2) rebuilds the `SEALED-EDGE` chain on every boot (ESTABLISHED,RELATED return, source `172.31.0.2` return, destination inside the edge subnet return, everything else drop) and jumps to it with `-s 172.31.0.0/24` from the top of `FORWARD` and, when the `DOCKER-USER` chain exists (Docker's iptables backend), from the top of `DOCKER-USER`, each inserted once. The script fails closed: it exits non-zero when a jump cannot be verified with `-C`, or when `DOCKER-USER` exists but `FORWARD` does not jump to it. Only the subnet and IP vary. A test runs the script against a fake `iptables`.

### app-compose.json (section 6)

Exactly `allowed_envs`, `docker_compose_file`, `gateway_enabled`, `key_provider` (`tpm`), `key_provider_id`, `kms_enabled`, `local_key_provider_enabled`, `manifest_version` (2), `name` (`sealed-<first 8 hex of configHash>`), `no_instance_id`, `pre_launch_script`, `public_logs`, `public_sysinfo`, `public_tcbinfo` (true), `runner`, `secure_time`, `storage_fs` (`ext4`), as CJSON with no trailing newline.

## Determinism and versioning

Every output is built from sorted inputs and serialized as CJSON or rendered from fixed templates; map iteration order never reaches the output. `composer.Version` (`1.2.0`) must equal `config.composerVersion`. Any change to composed bytes (this code, `runtime-images.json`, the Caddy template, the host rules) needs a new version, because approved stacks pin the old bytes. `testdata/golden/` pins the fixture stack's outputs (stackHash `0xb31a58ae...727d` for composer 1.2.0): when it fails on purpose, bump `Version`, then `go test ./runtime/composer -run Golden -update`; `-update` refuses to rewrite changed files while `summary.json` still records the current `Version`. The golden files double as cross-implementation vectors; consumers that copy them (`runtime/agent/test/fixtures/composer-golden`) copy them again.

## Lint

`lint.LintApp` (catalog source, including `waivers.yaml`), `lint.LintBundle` (release bundle; also checks each ref is exactly `<Options.Registry>/<name>@<digest>`, default the runtime images registry, and that SBOMs are present) and `lint.LintCatalog` (all apps, id matches directory, shared route names, `same_as` across apps). Errors block a release; warnings need review. `catalog/tools` wraps the CLI for app test suites.

License policy:

- Allowed for anything: rule 9 (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, LGPL, GPL-3.0, AGPL-3.0) plus the D-021 additions (PostgreSQL, Zlib, 0BSD, Unlicense, CC0-1.0, PSF-2.0, Python-2.0, BSL-1.0) and the D-050 additions (BlueOak-1.0.0, ZPL-2.1, CNRI-Python). GPL-2.0-or-later counts as allowed (usable under GPL-3.0).
- OS packages only (purl `pkg:deb`, `pkg:apk`, `pkg:rpm`, `pkg:alpm`, which also covers packages added with apk or apt in our own layers, such as git under GPL-2.0-only, bash and python3): GPL-2.0-only and other OSI-approved distribution licenses (D-021), and X11, BSD-4-Clause, OpenSSL, curl, IJG, Libpng, libtiff, FTL, bzip2, GFDL, Ruby and Vim (D-050).
- Data-only packages only: CC-BY-4.0, for the reviewed list `lint.DataOnlyPackages` (`caniuse-lite`).
- Anything else unrecognized: an error on non-OS packages in release mode (`RequireSBOM` or bundles), a warning otherwise and on OS packages.
- Hard fails: SSPL, BUSL, FSL, Elastic, Sustainable Use, Commons Clause, RSAL, proprietary and enterprise LicenseRefs. Expressions are evaluated with SPDX semantics: `OR` takes the best alternative (a banned alternative yields a warning to record the election), `AND` the worst, `WITH Commons-Clause` is banned.

`license_exceptions: [{decision: "D-0xx", paths: [...], reason}]` exempt SBOM packages and files that match `paths` from the license and excluded-path checks, with a warning each. Lint honours only the decision ids in `lint/exceptions.go`, which is empty: any entry is an error until a recorded decision adds its id there. D-019 is withdrawn (D-049), so crm gets none.

Other checks: zero digests (`unbuilt-image`), image sources with tags, unused images, empty `telemetry_off_env` (an error unless `telemetry_none_reason` explains, in at least 20 characters, why the app needs no switches), egress notes, `license_exclusions` for open-core upstreams (LiteLLM, Twenty, Appsmith, OpenHands), unused secrets, literal secret-like env values, SBOM package licenses and packages matching `license_exclusions` or `litellm_enterprise`, `enterprise/`, `@anthropic-ai/claude-agent-sdk`, release versions unsafe for asset names (`release-version`), the deprecated absolute `bootstrap.done_file` (`bootstrap`, warning), and `waivers.yaml` (`waivers`: a list or `{version: 1, waivers: [...]}`, each with a CVE or GHSA `id`, a manifest `image`, a `package`, a `reason` and an `expires` date that has not passed).

## CLI

```sh
go run ./runtime/composer/cmd/sealed-compose bundle --app-dir catalog/apps/crm --out crm.tar
go run ./runtime/composer/cmd/sealed-compose lint --catalog catalog/apps --require-sbom
go run ./runtime/composer/cmd/sealed-compose compose --config stack.json --app-dir catalog/apps/crm --print summary
go run ./runtime/composer/cmd/sealed-compose compose --config runtime/composer/testdata/config.json \
  --app-dir runtime/composer/testdata/apps/notes --app-dir runtime/composer/testdata/apps/llm-gateway \
  --fill-release-ids --out /tmp/stack
go run ./runtime/composer/cmd/sealed-compose version
```

`--print` selects `summary`, `app-compose`, `compose`, `egress`, `caddyfile`, `caddyfile-payment`, `stack`, `config` or `pre-launch`. `--fill-release-ids` is for local experiments only. `compose --require-built` fails on placeholder digests; `lint --registry` sets the registry bundle refs must use; `lint --json` prints findings as JSON.

## Tests

```sh
go test ./runtime/... ./catalog/...
go test ./runtime/composer/cjson -run '^$' -fuzz FuzzCanonicalize -fuzztime 30s
SEALED_CADDY_BIN=/path/to/caddy go test ./runtime/composer -run RealCaddy -v   # Caddy 2.11.x
node --test catalog/tools/*.test.mjs && python3 -m unittest discover -s catalog/tools
```

To build the Caddy binary for the real-Caddy test without touching the shared caches: in an empty module, `go get github.com/caddyserver/caddy/v2@v2.11.7` and `go build` a `main.go` that calls `caddycmd.Main()` with `modules/standard` imported, using `GOMODCACHE` and `GOCACHE` in a scratch directory (about 1.7 GB, removed after the build; the binary is 75 MB).

Covered: the shared CJSON vectors including error cases; the dstack golden vectors of `testdata/dstack/vectors.py` computed in Go; Solidity ABI id formulas against values from `cast`; byte-identical bundles across runs, mtimes and permissions; canonical-only bundle loading; determinism of `Compose` across runs, input orders and a three-app stack with every 1.2.0 feature; every single-byte change of a fragment, an egress policy, a manifest or the config changes `stackHash`, and changed values appear in the compose itself; network membership (two apps cannot reach each other's non-primary services; DNS and proxy per app network; egress callers for every address); exactly the declared secret files per service; `same_as`, `password`, `SEALED_PUBLIC_URL_<ROUTE>`, the relay on the attest host and `endpoints.relay`, routes to primaries, bootstrap restart and done files, volume owners, `debug` logging, agent device rules and the Caddy admin socket; capability hardening and fail-closed data and secret binds; every forbidden fragment key and mount; the host rules script against a fake `iptables`; `docker compose config --quiet` on several composed stacks (needs only the docker CLI); the real-Caddy run of the forward_auth gate, bearer passthrough, cookie and Authorization handling, request bodies, 503 while starting, the admin socket mode, the payment-needed switch and the relay on the attest host; release asset URLs and bundle fetch with a hash check and cache; the secret generators; the lint rules. Fixture apps live in `testdata/apps` (`notes`, a fake `llm-gateway`, a fake `inference-relay`).

## Differences from docs/INTERFACES.md (for its owner)

- Section 5: the config gains `debug` (boolean, default false, always in the canonical form); size bounds; VPC ranges may not overlap any VM network; with `llm-gateway`, `endpoints.relay` is the origin of `endpoints.relayAttest`.
- Section 6: app-compose.json at most 50 MiB; the service IP table above replaces "apps from .16 ..., app sub-services after that".
- Section 7: bundle `images[].ref` must be `<runtime-images registry>/<name>@<digest>`; release asset names as above (D-046).
- Section 12: one caller per address with the names above; allow-entry literal rules; `default_allow` at most 256 entries.
- Section 14: per-app networks; per-file secret mounts; Caddy without secrets; `SEALED_PUBLIC_URL_<ROUTE>`; `x-sealed-owner`; `same_as`; the `password` generator; `on_attest_host`; routes target the primary; service-name length and `--`; the forward_auth gate replaces `basic_auth`; the admin socket mode and owner; agent `device_cgroup_rules`; `logging` from `debug`; `sealed-stack/v1` as above; the ready gate `/run/sealed/ready/ok`; envexec `--secret`/`--optional-secret`; caddy edge IP `172.31.0.4`; upstream DNS `8.8.4.4`; `0x`-prefixed sbomHash values; `release_version` as the version hashed into releaseId.
- Section 15: host rules v2 (FORWARD and DOCKER-USER jumps, fails closed).
