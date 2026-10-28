import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import { findBlocks, render, unescapeFromCompose } from "../tools/embed-bootstrap.mjs";
import {
  composeConfig,
  dockerComposeAvailable,
  lintEgress,
  lintFragment,
  lintWaivers,
  loadApp,
  substituteImages,
  validateManifestSchema,
} from "./lib/catalog-lint.mjs";

const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const schemaPath = join(appDir, "../../schema/manifest.schema.json");
const app = loadApp(appDir);
const clone = (v) => structuredClone(v);

describe("manifest", () => {
  test("validates against catalog/schema/manifest.schema.json", () => {
    assert.deepEqual(validateManifestSchema(app.manifest, schemaPath), []);
  });

  test("pins every image by a real digest and keeps the D-020 Valkey choice", () => {
    for (const image of app.manifest.images) {
      assert.match(image.digest, /^sha256:[0-9a-f]{64}$/);
      assert.doesNotMatch(image.digest, /^sha256:0{64}$/, `${image.name} digest is pending`);
      assert.match(image.source, /:[^:/]+$/, `${image.name} source names its tag`);
    }
    assert.ok(!app.manifest.images.some((i) => /redis/.test(i.source)), "no Redis image (D-020)");
  });

  test("meters app hours from heartbeats behind the gate with the default maintainer", () => {
    assert.deepEqual(app.manifest.metering, { unit: "app_hour", source: "heartbeat" });
    assert.equal(app.manifest.maintainer.payout_address, "${MAINTAINER_DEFAULT_ADDRESS}");
    assert.equal(app.manifest.maintainer_share_bps, 2000);
    assert.deepEqual(app.manifest.routes.map((r) => [r.name, r.auth]), [["crm", "gate"]]);
  });

  test("turns telemetry, analytics, billing and enterprise calls off", () => {
    const off = app.manifest.telemetry_off_env;
    assert.equal(off.TELEMETRY_ENABLED, "false");
    assert.equal(off.ANALYTICS_ENABLED, "false");
    assert.equal(off.ENTERPRISE_API_URL, "");
    assert.equal(off.IS_BILLING_ENABLED, "false");
    assert.equal(off.IS_CONFIG_VARIABLES_IN_DB_ENABLED, "false");
    for (const name of ["ENTERPRISE_KEY", "ENTERPRISE_VALIDITY_TOKEN", "APP_SECRET"]) {
      assert.ok(!app.fragmentText.includes(name), `${name} must never be set`);
    }
  });

  test("generates secrets in the formats Twenty expects", () => {
    const gen = Object.fromEntries(app.manifest.secrets.map((s) => [s.name, s.generate]));
    assert.deepEqual(gen, {
      ENCRYPTION_KEY: "base64-32",
      PG_DATABASE_PASSWORD: "hex32",
      VALKEY_PASSWORD: "hex32",
      ADMIN_EMAIL: "none",
      ADMIN_PASSWORD: "none",
    });
  });
});

describe("compose fragment", () => {
  test("follows the INTERFACES section 14 rules", () => {
    assert.deepEqual(lintFragment(app), []);
  });

  test("server and worker share one environment apart from the worker switches", () => {
    const { "crm-server": server, "crm-worker": worker } = app.fragment.services;
    const { DISABLE_DB_MIGRATIONS, DISABLE_CRON_JOBS_REGISTRATION, ...rest } = worker.environment;
    assert.equal(DISABLE_DB_MIGRATIONS, "true");
    assert.equal(DISABLE_CRON_JOBS_REGISTRATION, "true");
    assert.deepEqual(rest, server.environment);
    assert.deepEqual(worker.entrypoint.slice(0, 3), server.entrypoint.slice(0, 3));
    assert.deepEqual(worker["x-sealed-secrets"], server["x-sealed-secrets"]);
  });

  test("keeps email, calendar, SSO providers, logic functions and multi-workspace off", () => {
    const env = app.fragment.services["crm-server"].environment;
    for (const key of [
      "IS_MULTIWORKSPACE_ENABLED", "IS_IMAP_SMTP_CALDAV_ENABLED", "MESSAGING_PROVIDER_GMAIL_ENABLED",
      "CALENDAR_PROVIDER_GOOGLE_ENABLED", "MESSAGING_PROVIDER_MICROSOFT_ENABLED", "CALENDAR_PROVIDER_MICROSOFT_ENABLED",
      "AUTH_GOOGLE_ENABLED", "AUTH_MICROSOFT_ENABLED",
    ]) {
      assert.equal(env[key], "false", key);
    }
    assert.equal(env.EMAIL_DRIVER, "LOGGER");
    assert.equal(env.LOGIC_FUNCTION_TYPE, "DISABLED");
    assert.equal(env.CODE_INTERPRETER_TYPE, "DISABLED");
  });

  test("builds SERVER_URL from the composer's public URL and keeps secrets out of env", () => {
    const script = app.fragment.services["crm-server"].entrypoint[2];
    assert.match(script, /SERVER_URL="\$\$SEALED_PUBLIC_URL_CRM"/);
    assert.match(script, /unset PG_DATABASE_PASSWORD VALKEY_PASSWORD/);
    assert.match(script, /exec \/app\/entrypoint\.sh "\$\$@"/);
  });

  test("embeds bootstrap/bootstrap.mjs byte for byte", async () => {
    const source = await readFile(join(appDir, "bootstrap/bootstrap.mjs"), "utf8");
    const embedded = app.fragment.services["crm-bootstrap"].command[2];
    assert.equal(unescapeFromCompose(embedded), source);
    assert.equal(render(app.fragmentText, () => source), app.fragmentText, "run node tools/embed-bootstrap.mjs");
    assert.deepEqual(findBlocks(app.fragmentText).map((b) => b.path), ["bootstrap/bootstrap.mjs"]);
  });

  test("the embedded bootstrap runs under node --input-type=module --eval", () => {
    const svc = app.fragment.services["crm-bootstrap"];
    const args = svc.command.map(unescapeFromCompose);
    const res = spawnSync(process.execPath, args, {
      encoding: "utf8",
      env: { PATH: process.env.PATH, SEALED_BOOTSTRAP: svc.environment.SEALED_BOOTSTRAP },
    });
    assert.equal(res.status, 1, res.stderr);
    assert.match(res.stdout, /\[crm-bootstrap\] failed: missing env CRM_BASE_URL|\[crm-bootstrap\] failed: missing env ADMIN_EMAIL/);
  });

  test("the embedded bootstrap only imports node: builtins", () => {
    const embedded = unescapeFromCompose(app.fragment.services["crm-bootstrap"].command[2]);
    const imports = [...embedded.matchAll(/from "([^"]+)"/g)].map((m) => m[1]);
    assert.ok(imports.length > 0);
    for (const spec of imports) assert.match(spec, /^node:/);
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
      assert.equal(
        services["crm-server"].image,
        "ghcr.io/sealed-dev/twenty@sha256:20b1010a975c42954d9f90698564795daf106da964bc95028836b09a8f424839",
      );
      assert.equal(services["crm-worker"].depends_on["crm-server"].condition, "service_healthy");
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
    ["a telemetry conflict", (f) => (f.services["crm-db"].environment.TELEMETRY_ENABLED = "true"), /conflicts with telemetry_off_env/],
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
    assert.deepEqual(lintEgress({ ...app.egress, default_allow: ["https://x.example"] }).length, 1);
  });

  test("waivers file is well formed and checks expiry", () => {
    assert.deepEqual(lintWaivers(app.waivers, app.manifest), []);
    const expired = { version: 1, waivers: [{ id: "CVE-1", image: "twenty", package: "p", expires: "2026-01-01", reason: "r" }] };
    assert.ok(lintWaivers(expired, app.manifest, new Date("2026-10-28")).some((e) => /expired/.test(e)));
    const unknown = { version: 1, waivers: [{ id: "CVE-1", image: "nope", package: "p", expires: "2027-01-01", reason: "r" }] };
    assert.ok(lintWaivers(unknown, app.manifest).some((e) => /not a manifest image/.test(e)));
  });
});

describe("licenses and docs", () => {
  test("ships the upstream license texts named in LICENSE-NOTICE", async () => {
    const notice = await readFile(join(appDir, "LICENSE-NOTICE"), "utf8");
    for (const file of notice.match(/LICENSES\/[\w.-]+/g)) {
      const text = await readFile(join(appDir, file), "utf8");
      assert.ok(text.length > 500, `${file} is empty`);
    }
    assert.match(notice, /https:\/\/github\.com\/twentyhq\/twenty\/tree\/twenty\/v2\.52\.0/);
    assert.match(notice, /present but never enabled/);
    assert.match(notice, /ENTERPRISE_KEY/);
    const twenty = await readFile(join(appDir, "LICENSES/twenty-v2.52.0-LICENSE"), "utf8");
    assert.match(twenty, /GNU AFFERO GENERAL PUBLIC LICENSE/);
    assert.match(twenty, /Twenty Application Exception/);
  });

  test("docs and manifest text contain no em-dashes", async () => {
    for (const file of ["README.md", "LICENSE-NOTICE", "manifest.yaml", "egress.yaml", "compose.fragment.yaml"]) {
      const text = await readFile(join(appDir, file), "utf8");
      assert.ok(!text.includes("—"), `${file} has an em-dash`);
    }
  });

  test("README pins match the manifest", async () => {
    const readme = await readFile(join(appDir, "README.md"), "utf8");
    for (const image of app.manifest.images) assert.ok(readme.includes(image.digest), `${image.name} digest missing from README`);
  });

  test("YAML files parse with unique keys", () => {
    for (const file of ["manifest.yaml", "compose.fragment.yaml", "egress.yaml", "waivers.yaml"]) {
      assert.doesNotThrow(() => parse(readFileSync(join(appDir, file), "utf8"), { uniqueKeys: true }), file);
    }
  });
});
