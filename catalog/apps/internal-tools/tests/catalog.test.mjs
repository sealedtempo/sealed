import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
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
const services = app.fragment.services;

describe("manifest", () => {
  test("validates against catalog/schema/manifest.schema.json", () => {
    assert.deepEqual(validateManifestSchema(app.manifest, schemaPath), []);
  });

  test("pins upstream images by digest and builds the ToolJet image from this directory", () => {
    for (const image of app.manifest.images) {
      assert.match(image.digest, /^sha256:[0-9a-f]{64}$/);
      if (image.source.startsWith("build:")) {
        assert.ok(existsSync(join(appDir, image.source.slice("build:".length), "Dockerfile")), image.source);
      } else {
        assert.doesNotMatch(image.digest, /^sha256:0{64}$/, `${image.name} digest is pending`);
        assert.match(image.source, /^docker\.io\/[^@]+:[^:/]+$/, `${image.name} source names its tag`);
      }
    }
    assert.ok(!app.manifest.images.some((i) => /redis|mongo|appsmith/.test(i.source)));
  });

  test("meters app hours from heartbeats behind the gate with the default maintainer", () => {
    assert.deepEqual(app.manifest.metering, { unit: "app_hour", source: "heartbeat" });
    assert.equal(app.manifest.maintainer.payout_address, "${MAINTAINER_DEFAULT_ADDRESS}");
    assert.equal(app.manifest.maintainer_share_bps, 2000);
    assert.deepEqual(app.manifest.routes.map((r) => [r.name, r.service, r.auth]), [["tools", "internal-tools-server", "gate"]]);
  });

  test("turns telemetry off and sinks marketplace and trial calls", () => {
    const off = app.manifest.telemetry_off_env;
    assert.equal(off.DISABLE_TOOLJET_TELEMETRY, "true");
    assert.equal(off.TOOLJET_MARKETPLACE_URL, "http://127.0.0.1:9");
    assert.equal(off.TJ_LICENSE_TRIAL_API, "http://127.0.0.1:9");
    assert.equal(off.SENTRY_DNS, "");
    for (const name of ["TJ_LICENSE", "TOOLJET_EDITION: \"ee\"", "STRIPE_API_KEY", "DISABLE_SSRF"]) {
      assert.ok(!app.fragmentText.includes(name), `${name} must never be set`);
    }
  });

  test("excludes enterprise directories, Oracle Instant Client and Redis binaries", () => {
    const ex = app.manifest.license_exclusions;
    for (const path of ["/app/server/ee/", "/app/frontend/ee/", "/opt/oracle/", "/usr/bin/redis-server"]) {
      assert.ok(ex.includes(path), path);
    }
  });
});

describe("compose fragment", () => {
  test("follows the INTERFACES section 14 rules", () => {
    assert.deepEqual(lintFragment(app), []);
  });

  test("closes sign-up in the measured environment and runs the CE edition", () => {
    const env = services["internal-tools-server"].environment;
    assert.equal(env.DISABLE_SIGNUPS, "true");
    assert.equal(env.SSO_DISABLE_SIGNUPS, "true");
    assert.equal(env.TOOLJET_EDITION, "ce");
    assert.equal(env.REDIS_HOST, "internal-tools-valkey");
    assert.equal(env.PGRST_HOST, "http://internal-tools-postgrest:3000");
    assert.equal(env.SAMPLE_PG_DB_USER, "tooljet_sample");
  });

  test("takes TOOLJET_HOST from the composer and drops PGPASSWORD before ToolJet starts", () => {
    const script = services["internal-tools-server"].entrypoint[2];
    assert.match(script, /export TOOLJET_HOST="\$\$SEALED_PUBLIC_URL_TOOLS"/);
    assert.match(script, /unset PGPASSWORD SAMPLE_DB_PASSWORD/);
    assert.match(script, /exec \/app\/server\/sealed-entrypoint\.sh "\$\$@"/);
  });

  test("PostgREST gets its password from PGPASSWORD, not from the URI", () => {
    const pg = services["internal-tools-postgrest"];
    assert.equal(pg.environment.PGRST_DB_URI, "postgres://postgres@internal-tools-db:5432/tooljet_db");
    assert.deepEqual(pg["x-sealed-secrets"].sort(), ["PGPASSWORD", "PGRST_JWT_SECRET"]);
  });

  test("the database init script creates a non-superuser sample role", () => {
    const script = unescapeFromCompose(services["internal-tools-db"].entrypoint[2]);
    assert.match(script, /CREATE ROLE tooljet_sample LOGIN CREATEDB PASSWORD :'pw';/);
    assert.doesNotMatch(script, /SUPERUSER/);
    const res = spawnSync("sh", ["-n", "-c", script], { encoding: "utf8" });
    assert.equal(res.status, 0, res.stderr);
  });

  test("every inline shell entrypoint is valid sh", () => {
    for (const [name, svc] of Object.entries(services)) {
      if (svc.entrypoint[0] !== "/bin/sh") continue;
      const res = spawnSync("sh", ["-n", "-c", unescapeFromCompose(svc.entrypoint[2])], { encoding: "utf8" });
      assert.equal(res.status, 0, `${name}: ${res.stderr}`);
    }
  });

  test("embeds bootstrap/bootstrap.mjs byte for byte", async () => {
    const source = await readFile(join(appDir, "bootstrap/bootstrap.mjs"), "utf8");
    assert.equal(unescapeFromCompose(services["internal-tools-bootstrap"].command[2]), source);
    assert.equal(render(app.fragmentText, () => source), app.fragmentText, "run node tools/embed-bootstrap.mjs");
    assert.deepEqual(findBlocks(app.fragmentText).map((b) => b.path), ["bootstrap/bootstrap.mjs"]);
  });

  test("the embedded bootstrap runs under node --input-type=module --eval", () => {
    const svc = services["internal-tools-bootstrap"];
    const res = spawnSync(process.execPath, svc.command.map(unescapeFromCompose), {
      encoding: "utf8",
      env: { PATH: process.env.PATH, SEALED_BOOTSTRAP: svc.environment.SEALED_BOOTSTRAP },
    });
    assert.equal(res.status, 1, res.stderr);
    assert.match(res.stdout, /\[internal-tools-bootstrap\] failed: missing env /);
    const imports = [...unescapeFromCompose(svc.command[2]).matchAll(/from "([^"]+)"/g)].map((m) => m[1]);
    for (const spec of imports) assert.match(spec, /^node:/);
  });

  test("docker compose accepts the fragment with registry images substituted", { skip: !dockerComposeAvailable() && "docker compose not installed" }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "tools-compose-"));
    try {
      const file = join(dir, "compose.yaml");
      await writeFile(file, substituteImages(app.fragmentText, app.manifest));
      const result = composeConfig(file, "sealed-internal-tools-check");
      assert.ok(result.ok, result.stderr);
      assert.deepEqual(Object.keys(result.config.services).sort(), Object.keys(services).sort());
      assert.equal(
        result.config.services["internal-tools-postgrest"].image,
        "ghcr.io/sealed-dev/postgrest@sha256:5f4ce744539bbba786b4e24dbbd95bdb2a956dcf568c5374995a0ff4a68f5bd2",
      );
      assert.match(result.config.services["internal-tools-server"].image, /^ghcr\.io\/sealed-dev\/tooljet@sha256:[0-9a-f]{64}$/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("egress, waivers, licenses and docs", () => {
  test("egress allows nothing by default and accepts customer additions", () => {
    assert.deepEqual(lintEgress(app.egress), []);
    assert.deepEqual(app.egress.default_allow, []);
    assert.equal(app.egress.customer_additions_allowed, true);
  });

  test("waivers file is well formed", () => {
    assert.deepEqual(lintWaivers(app.waivers, app.manifest), []);
  });

  test("ships the upstream license texts named in LICENSE-NOTICE", async () => {
    const notice = await readFile(join(appDir, "LICENSE-NOTICE"), "utf8");
    const files = notice.match(/LICENSES\/[\w.-]+/g);
    assert.equal(files.length, 4);
    for (const file of files) assert.ok((await readFile(join(appDir, file), "utf8")).length > 500, file);
    assert.match(await readFile(join(appDir, "LICENSES/tooljet-v3.20.251-lts-LICENSE"), "utf8"), /GNU AFFERO GENERAL PUBLIC LICENSE/);
    assert.match(notice, /https:\/\/github\.com\/ToolJet\/ToolJet\/tree\/v3\.20\.251-lts/);
  });

  test("docs and manifest text contain no em-dashes", async () => {
    for (const file of ["README.md", "LICENSE-NOTICE", "manifest.yaml", "egress.yaml", "compose.fragment.yaml", "images/tooljet-ce/Dockerfile"]) {
      assert.ok(!(await readFile(join(appDir, file), "utf8")).includes("—"), `${file} has an em-dash`);
    }
  });

  test("README pins match the manifest and the Dockerfile base", async () => {
    const readme = await readFile(join(appDir, "README.md"), "utf8");
    for (const image of app.manifest.images) assert.ok(readme.includes(image.digest), image.name);
    const base = /^FROM docker\.io\/tooljet\/tooljet-ce@(sha256:[0-9a-f]{64}) AS upstream$/m.exec(
      await readFile(join(appDir, "images/tooljet-ce/Dockerfile"), "utf8"),
    )[1];
    assert.ok(readme.includes(base));
    assert.ok((await readFile(join(appDir, "LICENSE-NOTICE"), "utf8")).includes(base));
  });

  test("YAML files parse with unique keys", () => {
    for (const file of ["manifest.yaml", "compose.fragment.yaml", "egress.yaml", "waivers.yaml"]) {
      assert.doesNotThrow(() => parse(readFileSync(join(appDir, file), "utf8"), { uniqueKeys: true }), file);
    }
  });
});
