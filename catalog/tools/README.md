# catalog/tools

Shared tooling for catalog app packages (integration brief item 25). It replaces the app-local copies of the catalog rules (`catalog/apps/crm/tests/lib/catalog-lint.mjs`, `catalog/apps/internal-tools/tests/lib/catalog-lint.mjs` and `catalog/apps/llm-gateway/tests/catalog_lint.py`). The rules live in one place, the composer's lint (`runtime/composer/lint`, run as `sealed-compose lint`); these files are thin wrappers that run it and return its findings. They add no rules of their own.

Both wrappers use the binary named by `SEALED_COMPOSE_BIN`, or build `runtime/composer/cmd/sealed-compose` once per process with `go build` from this checkout (or `SEALED_COMPOSER_DIR`) into a temporary directory that is removed on exit.

## Node (`catalog-lint.mjs`, Node 22+, no dependencies)

```js
import { findComposer, composerLint, errorsOf, composeStack, caddySite, caddyHandles, gateRoute } from "../../../tools/catalog-lint.mjs";

const composer = findComposer();                 // {bin} or {skip: reason}
const findings = composerLint(composer, appDir, { requireSbom: false });   // [{severity, app, file, field, code, message}]
assert.deepEqual(errorsOf(findings), []);
const stack = composeStack(composer, [appDir], outDir);   // {caddyfile, caddyfilePaymentNeeded, compose, stack, egress, config, appCompose, composePath}
const handles = caddyHandles(caddySite(stack.caddyfile, "crm.34-1-2-3.sslip.io"));
assert.equal(gateRoute(handles[""]), "crm");       // gated by sealed-agent's forward_auth (D-044)
```

Also exported: `runCompose`, `composerVersion`, `sampleConfig(appIds, version, overrides)` (its `endpoints.relay` is the relay attest origin, D-045), `memMiB`, `dockerComposeAvailable`, `composeConfig` (docker compose config with no daemon), `dockerDaemonAvailable`, `docker`, `waitForExit`.

CLI: `node catalog/tools/catalog-lint.mjs [--json] [--require-sbom] [--registry R] (--catalog catalog/apps | --app-dir DIR...)`; exit 1 on any error finding, 2 on usage or a missing composer.

## Python (`catalog_lint.py`, standard library only)

```python
sys.path.insert(0, os.path.join(REPO_ROOT, "catalog", "tools"))
import catalog_lint
findings = catalog_lint.composer_lint(app_dir, require_sbom=False)
assert catalog_lint.errors_of(findings) == []
```

CLI: `python3 catalog/tools/catalog_lint.py [--json] [--require-sbom] <app dir>...`.

## What the composer lint checks

Everything in `runtime/composer/README.md` (Lint): the manifest schema and semantic rules, the fragment rules, the egress policy, licenses (rule 9, D-021, D-050), license exclusions and exceptions, digests, telemetry switches, secrets (including `same_as` across the catalog with `--catalog`), SBOM package licenses and enterprise paths, release versions that are safe for release asset names, and `waivers.yaml` (a list, or `{version: 1, waivers: [...]}`; each waiver has a CVE or GHSA `id`, a manifest `image`, a `package`, a `reason` and an `expires` date that has not passed).

Not moved here: the docker contract helper (`contractCompose` in the crm and internal-tools suites), which runs an app outside the VM with upstream images and needs a YAML parser; it is app test code, not catalog rules.

## Tests

```sh
node --test catalog/tools/*.test.mjs
python3 -m unittest discover -s catalog/tools
```

Both need Go or `SEALED_COMPOSE_BIN`; they skip without it, and fail instead with `SEALED_REQUIRE_COMPOSER=1`. The docker compose check needs only the docker CLI with the compose plugin.
