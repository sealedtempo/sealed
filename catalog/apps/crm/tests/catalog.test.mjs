import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import { findBlocks, render, unescapeFromCompose } from "../tools/embed-bootstrap.mjs";
import {
  caddyHandles,
  caddySite,
  composeConfig,
  composerLint,
  composeStack,
  dockerComposeAvailable,
  findComposer,
  lintEgress,
  lintFragment,
  lintWaivers,
  loadApp,
  memMiB,
  substituteImages,
  validateManifestSchema,
} from "./lib/catalog-lint.mjs";

const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const schemaPath = join(appDir, "../../schema/manifest.schema.json");
const app = loadApp(appDir);
const clone = (v) => structuredClone(v);
const ESPO_SERVICES = ["crm-server", "crm-daemon", "crm-bootstrap"];
const ESPO_VOLUMES = [
  "crm-data:/var/www/html/data",
  "crm-custom:/var/www/html/custom",
  "crm-client-custom:/var/www/html/client/custom",
];
const ZERO = `sha256:${"0".repeat(64)}`;

describe("manifest (D-049a: EspoCRM)", () => {
  test("validates against catalog/schema/manifest.schema.json", () => {
    assert.deepEqual(validateManifestSchema(app.manifest, schemaPath), []);
  });

  test("EspoCRM is built from images/espocrm and pinned by digest (D-028); postgres is pinned", () => {
    const [espo, postgres] = app.manifest.images;
    assert.deepEqual([espo.name, espo.source, espo.license_spdx], ["espocrm", "build:images/espocrm", "AGPL-3.0-or-later"]);
    assert.match(espo.digest, /^sha256:[0-9a-f]{64}$/);
    assert.notEqual(espo.digest, ZERO);
    assert.ok(existsSync(join(appDir, "images/espocrm/Dockerfile")));
    assert.equal(postgres.source, "docker.io/library/postgres:16.15");
    assert.match(postgres.digest, /^sha256:[0-9a-f]{64}$/);
    assert.notEqual(postgres.digest, ZERO);
    assert.equal(app.manifest.images.length, 2, "no Redis or Valkey: EspoCRM needs neither");
    assert.ok(!app.fragmentText.includes("twenty"), "nothing of Twenty is left");
  });

  test("names EspoCRM as the upstream under AGPL-3.0-or-later", () => {
    assert.deepEqual(app.manifest.upstream, {
      repo: "https://github.com/espocrm/espocrm",
      version: "10.0.11",
      license_spdx: "AGPL-3.0-or-later",
      source_url: "https://github.com/espocrm/espocrm/tree/10.0.11",
    });
    assert.deepEqual(app.manifest.license_exclusions, [], "nothing is left out: the release has no enterprise code");
    assert.match(app.manifest.notes, /D-049a/);
  });

  test("meters app hours from heartbeats with the default maintainer", () => {
    assert.deepEqual(app.manifest.metering, { unit: "app_hour", source: "heartbeat" });
    assert.equal(app.manifest.maintainer.payout_address, "${MAINTAINER_DEFAULT_ADDRESS}");
    assert.equal(app.manifest.maintainer_share_bps, 2000);
  });

  test("the crm route is gated and points at Apache on 8080", () => {
    assert.deepEqual(app.manifest.routes.map((r) => [r.name, r.service, r.auth, r.internal_port, r.path_or_host]), [
      ["crm", "crm-server", "gate", 8080, "crm"],
    ]);
    assert.deepEqual(app.manifest.healthcheck, { service: "crm-server", http: "/api/v1/Settings", port: 8080, start_period_s: 300 });
  });

  test("declares at least the memory the fragment's mem_limit values add up to", () => {
    const total = Object.values(app.fragment.services).reduce((sum, svc) => sum + memMiB(svc.mem_limit), 0);
    assert.ok(Object.values(app.fragment.services).every((svc) => svc.mem_limit), "every service has a mem_limit");
    assert.ok(app.manifest.resources.memory_gb * 1024 >= total, `memory_gb ${app.manifest.resources.memory_gb} < ${total} MiB`);
  });

  test("telemetry_off_env is exactly the switch list sealed-espocrm enforces", () => {
    const script = readFileSync(join(appDir, "images/espocrm/sealed-espocrm.sh"), "utf8");
    const block = /SWITCHES="([^"]+)"/.exec(script)[1];
    const fromScript = Object.fromEntries(block.split("\n").map((l) => l.split("=")));
    assert.deepEqual(app.manifest.telemetry_off_env, fromScript);
    assert.equal(app.manifest.telemetry_off_env.ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS, "false");
    assert.equal(app.manifest.telemetry_off_env.ESPOCRM_CONFIG_ADMIN_PANEL_IFRAME_DISABLED, "true");
  });

  test("generates the database password and the admin password (brief item 7)", () => {
    const gen = Object.fromEntries(app.manifest.secrets.map((s) => [s.name, s.generate]));
    assert.deepEqual(gen, { PG_DATABASE_PASSWORD: "hex32", ADMIN_PASSWORD: "password" });
    const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
    assert.ok(schema.properties.secrets.items.properties.generate.enum.includes("password"));
  });
});

describe("compose fragment", () => {
  test("follows the INTERFACES section 14 rules", () => {
    assert.deepEqual(lintFragment(app), []);
  });

  test("the three EspoCRM services share the image and the three data volumes", () => {
    for (const name of ESPO_SERVICES) {
      const svc = app.fragment.services[name];
      assert.equal(svc.image, "{{image:espocrm}}", name);
      for (const v of ESPO_VOLUMES) assert.ok(svc.volumes.includes(v), `${name} ${v}`);
      assert.ok(svc["x-sealed-secrets"].includes("PG_DATABASE_PASSWORD"), name);
      assert.equal(svc.user, undefined, `${name} starts as root only to hand the volumes to www-data`);
    }
    assert.deepEqual(
      ESPO_SERVICES.map((n) => app.fragment.services[n].entrypoint),
      [["/usr/local/bin/sealed-espocrm", "server"], ["/usr/local/bin/sealed-espocrm", "daemon"], ["/usr/local/bin/sealed-espocrm", "bootstrap"]],
    );
  });

  test("only the bootstrap sees the admin password and the bootstrap volume", () => {
    for (const [name, svc] of Object.entries(app.fragment.services)) {
      const hasAdmin = (svc["x-sealed-secrets"] ?? []).includes("ADMIN_PASSWORD");
      assert.equal(hasAdmin, name === "crm-bootstrap", name);
      const hasState = (svc.volumes ?? []).some((v) => v.startsWith("crm-bootstrap:"));
      assert.equal(hasState, name === "crm-bootstrap", name);
    }
  });

  test("the daemon starts after the bootstrap; nothing depends on crm-server being healthy first", () => {
    const deps = (n) => app.fragment.services[n].depends_on;
    assert.deepEqual(deps("crm-daemon"), { "crm-db": { condition: "service_healthy" }, "crm-bootstrap": { condition: "service_completed_successfully" } });
    assert.deepEqual(deps("crm-bootstrap"), { "crm-db": { condition: "service_healthy" } });
    assert.deepEqual(deps("crm-server"), { "crm-db": { condition: "service_healthy" } });
  });

  test("the bootstrap talks to crm-server on the route port and names its accounts", () => {
    const env = app.fragment.services["crm-bootstrap"].environment;
    assert.equal(env.CRM_BASE_URL, `http://crm-server:${app.manifest.routes[0].internal_port}`);
    assert.equal(env.STATE_DIR, "/sealed-bootstrap");
    assert.equal(env.ADMIN_USERNAME, "admin");
    assert.equal(env.API_USER_NAME, "sealed-customer");
    assert.equal(app.manifest.bootstrap.done_file, "crm-bootstrap/done.json");
  });

  test("the healthcheck probes the manifest's path on the route port without the proxy", () => {
    const test_ = app.fragment.services["crm-server"].healthcheck.test;
    assert.equal(test_[0], "CMD");
    assert.deepEqual(test_.slice(1, 3), ["php", "-r"]);
    assert.ok(test_[3].includes(`http://127.0.0.1:8080${app.manifest.healthcheck.http}`));
  });

  test("the database belongs to the espocrm role named in the override file", () => {
    const db = app.fragment.services["crm-db"];
    assert.equal(db.environment.POSTGRES_DB, "espocrm");
    assert.equal(db.environment.POSTGRES_USER, "espocrm");
    const script = readFileSync(join(appDir, "images/espocrm/sealed-espocrm.sh"), "utf8");
    assert.match(script, /'dbname' => 'espocrm',\n\s+'user' => 'espocrm',/);
    assert.match(db.entrypoint[2], /unset PG_DATABASE_PASSWORD/);
  });

  test("embeds bootstrap/bootstrap.mjs byte for byte", async () => {
    const source = await readFile(join(appDir, "bootstrap/bootstrap.mjs"), "utf8");
    const embedded = app.fragment.services["crm-bootstrap"].command[3];
    assert.equal(unescapeFromCompose(embedded), source);
    assert.equal(render(app.fragmentText, () => source), app.fragmentText, "run node tools/embed-bootstrap.mjs");
    assert.deepEqual(findBlocks(app.fragmentText).map((b) => b.path), ["bootstrap/bootstrap.mjs"]);
  });

  test("the embedded bootstrap runs under node --input-type=module --eval", () => {
    const svc = app.fragment.services["crm-bootstrap"];
    const [node, ...args] = svc.command.map(unescapeFromCompose);
    assert.equal(node, "node");
    const res = spawnSync(process.execPath, args, {
      encoding: "utf8",
      env: { PATH: process.env.PATH, SEALED_BOOTSTRAP: svc.environment.SEALED_BOOTSTRAP },
    });
    assert.equal(res.status, 1, res.stderr);
    assert.match(res.stdout, /\[crm-bootstrap\] failed: missing env CRM_BASE_URL/);
  });

  test("the embedded bootstrap only imports node: builtins and stays on Node 20 APIs", () => {
    const embedded = unescapeFromCompose(app.fragment.services["crm-bootstrap"].command[3]);
    const imports = [...embedded.matchAll(/from "([^"]+)"/g)].map((m) => m[1]);
    assert.ok(imports.length > 0);
    for (const spec of imports) assert.match(spec, /^node:/);
    // Debian trixie ships Node 20.19: no APIs newer than that.
    assert.doesNotMatch(embedded, /import\.meta\.dirname|Promise\.try|RegExp\.escape|Iterator\.from|process\.getBuiltinModule/);
  });

  test("docker compose accepts the fragment with registry images substituted", { skip: !dockerComposeAvailable() && "docker compose not installed" }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "crm-compose-"));
    try {
      const file = join(dir, "compose.yaml");
      await writeFile(file, substituteImages(app.fragmentText, app.manifest));
      const result = composeConfig(file, "sealed-crm-check");
      assert.ok(result.ok, result.stderr);
      const services = result.config.services;
      assert.deepEqual(Object.keys(services).sort(), Object.keys(app.fragment.services).sort());
      assert.equal(services["crm-db"].image, `ghcr.io/sealedtempo/postgres@${app.manifest.images[1].digest}`);
      assert.equal(services["crm-daemon"].depends_on["crm-bootstrap"].condition, "service_completed_successfully");
      assert.equal(services["crm-server"].healthcheck.start_period, "5m0s");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("fragment linter catches violations", () => {
  const cases = [
    ["published ports", (f) => (f.services["crm-db"].ports = ["5432:5432"]), /crm-db\.ports is not allowed/],
    ["a bind mount", (f) => f.services["crm-db"].volumes.push("/var/run/docker.sock:/var/run/docker.sock"), /bind mount/],
    ["an unprefixed service", (f) => (f.services.db = f.services["crm-db"]), /services\.db must start with crm-/],
    ["a tag instead of an image ref", (f) => (f.services["crm-db"].image = "postgres:16"), /must be \{\{image:<name>\}\}/],
    ["an unknown image", (f) => (f.services["crm-db"].image = "{{image:mysql}}"), /unknown image mysql/],
    ["an unknown secret", (f) => f.services["crm-db"]["x-sealed-secrets"].push("OTHER"), /secret OTHER not listed/],
    ["a single dollar", (f) => (f.services["crm-db"].environment.PGDATA = "${HOME}/x"), /not doubled/],
    ["a missing entrypoint", (f) => delete f.services["crm-db"].entrypoint, /crm-db\.entrypoint must be an explicit list/],
    ["a cross-app dependency", (f) => (f.services["crm-server"].depends_on["llm-gateway"] = { condition: "service_started" }), /llm-gateway is not a service of this app/],
    ["privileged mode", (f) => (f.services["crm-db"].privileged = true), /privileged is not allowed/],
    ["a networks key", (f) => (f.networks = {}), /top-level key networks/],
    ["a secret passed as env", (f) => (f.services["crm-db"].environment.ADMIN_PASSWORD = "x"), /is a secret name/],
    ["a telemetry conflict", (f) => (f.services["crm-server"].environment = { ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS: "true" }), /conflicts with telemetry_off_env/],
  ];
  for (const [name, mutate, expected] of cases) {
    test(name, () => {
      const fragment = clone(app.fragment);
      mutate(fragment);
      const errors = lintFragment({ ...app, fragment });
      assert.ok(errors.some((e) => expected.test(e)), errors.join("\n"));
    });
  }

  test("a manifest route to an unknown service", () => {
    const manifest = clone(app.manifest);
    manifest.routes[0].service = "crm-nope";
    assert.ok(lintFragment({ ...app, manifest }).some((e) => /routes\[0\]\.service names unknown service/.test(e)));
  });

  test("a done file outside the app volumes", () => {
    const manifest = clone(app.manifest);
    manifest.bootstrap.done_file = "/etc/done";
    assert.ok(lintFragment({ ...app, manifest }).some((e) => /done_file/.test(e)));
  });
});

describe("egress and waivers", () => {
  test("egress allows nothing by default and accepts customer additions", () => {
    assert.deepEqual(lintEgress(app.egress), []);
    assert.deepEqual(app.egress.default_allow, []);
    assert.equal(app.egress.customer_additions_allowed, true);
    assert.match(app.egress.notes, /s\.espocrm\.com/);
    assert.deepEqual(lintEgress({ ...app.egress, default_allow: ["https://x.example"] }).length, 1);
  });

  test("waivers file is well formed and checks expiry", () => {
    assert.deepEqual(lintWaivers(app.waivers, app.manifest), []);
    const expired = { version: 1, waivers: [{ id: "CVE-1", image: "espocrm", package: "p", expires: "2026-01-01", reason: "r" }] };
    assert.ok(lintWaivers(expired, app.manifest, new Date("2026-10-28")).some((e) => /expired/.test(e)));
    const unknown = { version: 1, waivers: [{ id: "CVE-1", image: "twenty", package: "p", expires: "2027-01-01", reason: "r" }] };
    assert.ok(lintWaivers(unknown, app.manifest).some((e) => /not a manifest image/.test(e)));
  });
});

describe("licenses and docs", () => {
  test("ships the license texts named in LICENSE-NOTICE", async () => {
    const notice = await readFile(join(appDir, "LICENSE-NOTICE"), "utf8");
    const files = notice.match(/LICENSES\/[\w.-]+/g);
    assert.deepEqual([...new Set(files)].sort(), ["LICENSES/espocrm-10.0.11-LICENSE.txt", "LICENSES/postgresql-16.15-COPYRIGHT"]);
    for (const file of files) {
      const text = await readFile(join(appDir, file), "utf8");
      assert.ok(text.length > 500, `${file} is empty`);
    }
    const espo = await readFile(join(appDir, "LICENSES/espocrm-10.0.11-LICENSE.txt"), "utf8");
    assert.match(espo, /GNU AFFERO GENERAL PUBLIC LICENSE\s+Version 3, 19 November 2007/);
    assert.match(notice, /https:\/\/github\.com\/espocrm\/espocrm\/tree\/10\.0\.11/);
    assert.match(notice, /32d559ba86d3be607599d1325c359668c1178850/);
    assert.match(notice, /section 7\(b\)/);
    assert.match(notice, /Enterprise code: none/);
  });

  test("docs and manifest text contain no em-dashes", async () => {
    const files = [
      "README.md", "LICENSE-NOTICE", "manifest.yaml", "egress.yaml", "compose.fragment.yaml",
      "images/espocrm/Dockerfile", "images/espocrm/apache-sealed.conf", "images/espocrm/sealed-espocrm.sh",
      "images/espocrm/php-sealed.ini", "bootstrap/bootstrap.mjs", "scripts/a6-crm.mjs",
    ];
    for (const file of files) {
      const text = await readFile(join(appDir, file), "utf8");
      assert.ok(!text.includes("\u2014"), `${file} has an em-dash`);
    }
  });

  test("README pins match the manifest and the Dockerfile", async () => {
    const readme = await readFile(join(appDir, "README.md"), "utf8");
    const dockerfile = await readFile(join(appDir, "images/espocrm/Dockerfile"), "utf8");
    assert.ok(readme.includes(app.manifest.images[1].digest), "postgres digest missing from README");
    for (const pin of [/sha256:[0-9a-f]{64}/.exec(dockerfile.match(/^FROM .*$/m)[0])?.[0], "cdd04f7efa52a59025ef824c75b06e0a84cf986724a8c5bc4b56fcd2ce8e0ab1", "20261027T000000Z"]) {
      if (pin) assert.ok(readme.includes(pin.replace(/^sha256:/, "")), `${pin} missing from README`);
    }
    assert.match(readme, /## D-049a/);
  });

  test("YAML files parse with unique keys", () => {
    for (const file of ["manifest.yaml", "compose.fragment.yaml", "egress.yaml", "waivers.yaml"]) {
      assert.doesNotThrow(() => parse(readFileSync(join(appDir, file), "utf8"), { uniqueKeys: true }), file);
    }
  });
});

const composer = findComposer(appDir);
describe("the real composer (runtime/composer)", { skip: composer.skip }, () => {
  test("sealed-compose lint blocks the release only on the unbuilt EspoCRM image (D-028)", () => {
    const findings = composerLint(composer, appDir);
    const errors = findings.filter((f) => f.severity === "error").map((f) => `${f.code} ${f.field ?? ""}`.trim());
    const unbuilt = app.manifest.images[0].digest === ZERO;
    assert.deepEqual(errors, unbuilt ? ["unbuilt-image images[0].digest"] : []);
    const warnings = new Set(findings.filter((f) => f.severity === "warning").map((f) => f.code));
    assert.deepEqual([...warnings], ["sbom-missing"], "only the SBOMs CI generates are missing");
  });

  describe("composed stack", async () => {
    const out = await mkdtemp(join(tmpdir(), "crm-composed-"));
    after(() => rm(out, { recursive: true, force: true }));
    const stack = composeStack(composer, [appDir], out);
    const services = stack.compose.services;

    test("the Caddyfile gates crm and proxies only to Apache on 8080", () => {
      const site = caddySite(stack.caddyfile, "crm.34-1-2-3.sslip.io");
      assert.ok(site, stack.caddyfile);
      const handles = caddyHandles(site);
      assert.deepEqual(Object.keys(handles), [""]);
      // The gate is forward_auth to sealed-agent (D-044); basic_auth is gone with composer 1.2.0.
      assert.match(handles[""], /forward_auth sealed-agent:7070 \{[\s\S]*uri \/v1\/gate\?route=crm/);
      assert.doesNotMatch(stack.caddyfile, /basic_auth|GATE_PASSWORD_BCRYPT/);
      assert.match(handles[""], /reverse_proxy crm-server:8080/);
      assert.equal((stack.caddyfile.match(/crm-server:\d+/g) ?? []).filter((u) => u !== "crm-server:8080").length, 0);
    });

    test("volumes land on the data disk and the bootstrap restarts on failure", () => {
      for (const name of ESPO_SERVICES) {
        const data = services[name].volumes.find((v) => v.target === "/var/www/html/data");
        assert.equal(data.source, "/mnt/sealed-data/crm/crm-data", name);
      }
      assert.equal(services["crm-bootstrap"].restart, "on-failure");
      const crm = stack.stack.apps.find((a) => a.id === "crm");
      assert.equal(crm.bootstrap.doneFile, "crm-bootstrap/done.json");
      assert.equal(crm.bootstrap.service, "crm-bootstrap");
      assert.deepEqual(crm.routes.map((r) => [r.auth, r.port, r.service]), [["gate", 8080, "crm-server"]]);
    });

    test("the telemetry switches reach every EspoCRM service", () => {
      for (const name of ESPO_SERVICES) {
        for (const [k, v] of Object.entries(app.manifest.telemetry_off_env)) assert.equal(services[name].environment[k], v, `${name} ${k}`);
      }
    });

    test("the composer wraps every entrypoint in envexec", () => {
      for (const name of ESPO_SERVICES) {
        const ep = services[name].entrypoint;
        assert.deepEqual(ep.slice(0, 3), ["/sealed/bin/envexec", "--app", "crm"], name);
        const sep = ep.indexOf("--");
        assert.deepEqual(ep.slice(sep + 1), app.fragment.services[name].entrypoint, name);
      }
    });

    test("docker compose accepts the composed document", { skip: !dockerComposeAvailable() && "docker compose not installed" }, () => {
      const result = composeConfig(stack.composePath, "sealed-crm-composed");
      assert.ok(result.ok, result.stderr);
    });

    // Brief item 8. sealed-espocrm stops with a clear message until the composer sets it.
    const urlSet = ESPO_SERVICES.every((n) => services[n].environment?.SEALED_PUBLIC_URL_CRM);
    test("the composer sets SEALED_PUBLIC_URL_CRM on every crm service", { todo: !urlSet && "brief item 8 is not in the composer of this checkout yet" }, () => {
      for (const name of ESPO_SERVICES) {
        assert.equal(services[name].environment.SEALED_PUBLIC_URL_CRM, "https://crm.34-1-2-3.sslip.io", name);
      }
    });
  });
});
