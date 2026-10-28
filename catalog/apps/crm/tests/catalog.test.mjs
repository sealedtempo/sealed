import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { chmod, cp, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
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

  test("meters app hours from heartbeats with the default maintainer", () => {
    assert.deepEqual(app.manifest.metering, { unit: "app_hour", source: "heartbeat" });
    assert.equal(app.manifest.maintainer.payout_address, "${MAINTAINER_DEFAULT_ADDRESS}");
    assert.equal(app.manifest.maintainer_share_bps, 2000);
  });

  test("the crm route uses the gate the composer allows, pending interface change 6", () => {
    // The basic-auth gate refuses and strips the "Authorization: Bearer" header Twenty sends on
    // every signed-in call (a6.test.mjs shows both modes; the todo test below flips once the
    // composer accepts bearer-passthrough for crm).
    assert.deepEqual(app.manifest.routes.map((r) => [r.name, r.auth, r.internal_port]), [["crm", "gate", 3000]]);
  });

  test("declares at least the memory the fragment's mem_limit values add up to", () => {
    const total = Object.values(app.fragment.services).reduce((sum, svc) => sum + memMiB(svc.mem_limit), 0);
    assert.ok(Object.values(app.fragment.services).every((svc) => svc.mem_limit), "every service has a mem_limit");
    assert.ok(app.manifest.resources.memory_gb * 1024 >= total, `memory_gb ${app.manifest.resources.memory_gb} < ${total} MiB`);
  });

  test("keeps license_exclusions honest: Twenty has no path that is left out (D-019 open)", () => {
    assert.deepEqual(app.manifest.license_exclusions, []);
    assert.match(app.manifest.notes, /Release blocked on D-019/);
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
    // Same connection setup; only crm-server waits for the bootstrap on the setup port.
    const [serverScript, workerScript] = [server, worker].map((s) => s.entrypoint[2]);
    const setupStart = serverScript.indexOf("done_file=");
    assert.ok(setupStart > 0);
    assert.equal(workerScript, `${serverScript.slice(0, setupStart)}exec /app/entrypoint.sh "$$@"\n`);
    assert.deepEqual(worker.entrypoint.slice(0, 2), server.entrypoint.slice(0, 2));
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

  test("valkey gets its password from a tmpfs config file, never from argv", async () => {
    const svc = app.fragment.services["crm-valkey"];
    const script = unescapeFromCompose(svc.entrypoint[2]);
    assert.deepEqual(svc.tmpfs, ["/run/valkey"]);
    assert.doesNotMatch(script, /requirepass "\$\$?pass"|--requirepass/);
    assert.doesNotMatch(svc.healthcheck.test[1], / -a /);
    assert.match(svc.healthcheck.test[1], /^VALKEYCLI_AUTH="\$\$\(cat \/run\/sealed\/secrets\/crm\/VALKEY_PASSWORD\)" valkey-cli ping/);

    // Run the script with stand-ins for chown and tini that record what valkey would see.
    const dir = await mkdtemp(join(tmpdir(), "crm-valkey-"));
    try {
      const bin = join(dir, "bin");
      await writeFile(join(dir, "placeholder"), "");
      await spawnSync("mkdir", [bin]);
      await writeFile(join(bin, "chown"), "#!/bin/sh\nexit 0\n");
      await writeFile(join(bin, "tini"), `#!/bin/sh\nshift\nprintf '%s\\n' "$@" > "${dir}/argv"\nenv > "${dir}/env"\n`);
      await chmod(join(bin, "chown"), 0o755);
      await chmod(join(bin, "tini"), 0o755);
      const conf = join(dir, "valkey.conf");
      const body = script.replaceAll("/run/valkey/valkey.conf", conf);
      const res = spawnSync("/bin/sh", ["-c", body, "crm-valkey", ...svc.command], {
        env: { PATH: `${bin}:${process.env.PATH}`, VALKEY_PASSWORD: "0123abcd".repeat(8) },
        encoding: "utf8",
      });
      assert.equal(res.status, 0, res.stderr);
      const argv = (await readFile(join(dir, "argv"), "utf8")).trim().split("\n");
      assert.deepEqual(argv, ["docker-entrypoint.sh", "valkey-server", conf, "--maxmemory-policy", "noeviction", "--appendonly", "yes"]);
      assert.equal(await readFile(conf, "utf8"), `requirepass "${"0123abcd".repeat(8)}"\n`);
      assert.equal((await stat(conf)).mode & 0o777, 0o600);
      assert.doesNotMatch(await readFile(join(dir, "env"), "utf8"), /VALKEY_PASSWORD/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
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
        "ghcr.io/sealedtempo/twenty@sha256:20b1010a975c42954d9f90698564795daf106da964bc95028836b09a8f424839",
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
    assert.doesNotMatch(notice, /never enabled/, "the enterprise-marked modules do run as gating code");
    assert.match(notice, /some of them run on every start/);
    assert.match(notice, /does not mirror or publish this app until the decision/);
    assert.match(notice, /ENTERPRISE_KEY/);
    const twenty = await readFile(join(appDir, "LICENSES/twenty-v2.52.0-LICENSE"), "utf8");
    assert.match(twenty, /GNU AFFERO GENERAL PUBLIC LICENSE/);
    assert.match(twenty, /Twenty Application Exception/);
  });

  test("docs and manifest text contain no em-dashes", async () => {
    for (const file of ["README.md", "LICENSE-NOTICE", "manifest.yaml", "egress.yaml", "compose.fragment.yaml"]) {
      const text = await readFile(join(appDir, file), "utf8");
      assert.ok(!text.includes("\u2014"), `${file} has an em-dash`);
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

const composer = findComposer(appDir);
describe("the real composer (runtime/composer, ws/composer)", { skip: composer.skip }, () => {
  test("sealed-compose lint finds only the D-019 block on crm", () => {
    const findings = composerLint(composer, appDir);
    const errors = findings.filter((f) => f.severity === "error").map((f) => `${f.code} ${f.field ?? ""}`.trim());
    // The composer requires license_exclusions for open-core upstreams. Twenty has nothing that
    // is left out of the image, so the release stays blocked until D-019 is decided. Any other
    // error means this app drifted from the composer's rules.
    assert.deepEqual(errors, ["license-exclusions license_exclusions"]);
    const warnings = new Set(findings.filter((f) => f.severity === "warning").map((f) => f.code));
    assert.deepEqual([...warnings], ["sbom-missing"], "only the SBOMs CI generates are missing");
  });

  describe("composed stack", async () => {
    const out = await mkdtemp(join(tmpdir(), "crm-composed-"));
    after(() => rm(out, { recursive: true, force: true }));
    const stack = composeStack(composer, [appDir], out);
    const services = stack.compose.services;

    test("the Caddyfile gates crm with basic auth and never routes to the setup port", () => {
      const site = caddySite(stack.caddyfile, "crm.34-1-2-3.sslip.io");
      assert.ok(site, stack.caddyfile);
      const handles = caddyHandles(site);
      assert.deepEqual(Object.keys(handles), [""]);
      assert.match(handles[""], /basic_auth \{\n\t\t\tsealed \{env\.GATE_PASSWORD_BCRYPT\}/);
      assert.match(handles[""], /reverse_proxy crm-server:3000 \{\n\t\t\theader_up -Authorization/);
      assert.doesNotMatch(stack.caddyfile, /crm-server:3001/, "no route reaches the setup port");
    });

    test("crm-server sees done.json read-only and keeps the fragment's healthcheck", () => {
      const server = services["crm-server"];
      const mount = server.volumes.find((v) => v.target === "/sealed-bootstrap");
      assert.equal(mount.source, "/mnt/sealed-data/crm/crm-bootstrap");
      assert.equal(mount.read_only, true);
      assert.equal(server.environment.CRM_SETUP_PORT, "3001");
      assert.deepEqual(server.healthcheck.test, app.fragment.services["crm-server"].healthcheck.test);
      assert.equal(services["crm-bootstrap"].restart, "on-failure");
      const crm = stack.stack.apps.find((a) => a.id === "crm");
      assert.equal(crm.bootstrap.doneFile, "crm-bootstrap/done.json");
      assert.equal(crm.bootstrap.service, "crm-bootstrap");
      assert.deepEqual(crm.routes.map((r) => [r.auth, r.port, r.service]), [["gate", 3000, "crm-server"]]);
    });

    test("valkey's password stays out of the composed argv", () => {
      const valkey = services["crm-valkey"];
      assert.ok(!JSON.stringify(valkey.entrypoint).includes("--requirepass"));
      assert.ok(!JSON.stringify(valkey.command).includes("requirepass"));
    });

    test("docker compose accepts the composed document", { skip: !dockerComposeAvailable() && "docker compose not installed" }, () => {
      const result = composeConfig(stack.composePath, "sealed-crm-composed");
      assert.ok(result.ok, result.stderr);
    });

    // Interface change 6, option (b): with bearer-passthrough the composed site must send
    // bearer requests to crm-server unchanged and gate the rest, as fake-gate.mjs assumes.
    test("bearer-passthrough for crm composes into a bearer handle plus the gate", { todo: "interface change 6: the composer allows bearer-passthrough only for the gateway route" }, async () => {
      const variant = await mkdtemp(join(tmpdir(), "crm-bearer-"));
      try {
        await cp(appDir, join(variant, "crm"), { recursive: true, filter: (src) => !src.includes("node_modules") });
        const manifestPath = join(variant, "crm", "manifest.yaml");
        const text = await readFile(manifestPath, "utf8");
        await writeFile(manifestPath, text.replace(/^    auth: gate$/m, "    auth: bearer-passthrough"));
        const composed = composeStack(composer, [join(variant, "crm")], join(variant, "out"));
        const handles = caddyHandles(caddySite(composed.caddyfile, "crm.34-1-2-3.sslip.io"));
        assert.deepEqual(Object.keys(handles).sort(), ["", "@r0_bearer"]);
        assert.match(composed.caddyfile, /@r0_bearer \{\n\t\theader Authorization "Bearer \*"\n\t\}/);
        assert.match(handles["@r0_bearer"], /reverse_proxy crm-server:3000/);
        assert.doesNotMatch(handles["@r0_bearer"], /basic_auth|header_up -Authorization/);
        assert.match(handles[""], /basic_auth/);
      } finally {
        await rm(variant, { recursive: true, force: true });
      }
    });

    // Interface change 1: until the composer sets SEALED_PUBLIC_URL_<ROUTE>, the ":?" guard in
    // the entrypoints stops crm-server, crm-worker and crm-bootstrap on purpose.
    test("the composer sets SEALED_PUBLIC_URL_CRM on every crm service", { todo: "interface change 1 is not in the composer yet" }, () => {
      for (const name of ["crm-server", "crm-worker", "crm-bootstrap"]) {
        assert.equal(services[name].environment.SEALED_PUBLIC_URL_CRM, "https://crm.34-1-2-3.sslip.io", name);
      }
    });
  });
});
