import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import { loadConfig } from "../bootstrap/bootstrap.mjs";
import { findBlocks, render, unescapeFromCompose } from "../tools/embed-bootstrap.mjs";
import { checkWaivers, composeConfig, dockerComposeAvailable, loadApp, memMiB, volumeOwners } from "./lib/app.mjs";
import {
  caddySite,
  composerLint,
  composeStack,
  envexecSecrets,
  findComposer,
  secretMounts,
  unexpectedFindings,
} from "./lib/composer.mjs";

// The catalog rules (schema, fragment rules of INTERFACES section 14, egress policy, licenses) are
// checked by the real composer below; these tests add what is specific to this app.
const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const app = loadApp(appDir);
const services = app.fragment.services;

describe("manifest", () => {
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

  test("excludes enterprise directories, Oracle Instant Client, Redis binaries and Redis modules", () => {
    const ex = app.manifest.license_exclusions;
    for (const path of ["/ee/", "/app/server/ee/", "/app/frontend/ee/", "/opt/oracle/", "/usr/bin/redis-server", "/usr/lib/redis/", "/etc/redis/"]) {
      assert.ok(ex.includes(path), path);
    }
    // License audit F7: "/ee/" as a path segment, never a bare "ee/" (which would match tree/ or free/).
    assert.ok(!ex.includes("ee/"));
  });

  test("generates the admin password with the password generator, within ToolJet's limits", () => {
    const secrets = Object.fromEntries(app.manifest.secrets.map((s) => [s.name, s]));
    // Integration brief item 7: 24 characters from [A-Za-z0-9].
    assert.equal(secrets.ADMIN_PASSWORD.generate, "password");
    assert.equal(secrets.ADMIN_EMAIL.generate, "none");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const generated = Array.from(randomBytes(24), (b) => alphabet[b % alphabet.length]).join("");
    const cfg = loadConfig({ ADMIN_EMAIL: "a@example.com", ADMIN_PASSWORD: generated, SEALED_PUBLIC_URL_TOOLS: "https://tools.example.com", TOOLS_BASE_URL: "http://x:3000", STATE_DIR: "/tmp" });
    assert.equal(cfg.password, generated);
    for (const s of app.manifest.secrets) assert.equal(s.same_as, undefined, s.name);
  });

  test("declares at least the memory the fragment's mem_limit values add up to", () => {
    assert.ok(Object.values(services).every((svc) => svc.mem_limit), "every service has a mem_limit");
    const total = Object.values(services).reduce((sum, svc) => sum + memMiB(svc.mem_limit), 0);
    assert.ok(app.manifest.resources.memory_gb * 1024 >= total, `memory_gb ${app.manifest.resources.memory_gb} < ${total} MiB`);
  });
});

describe("compose fragment", () => {
  test("gives the bootstrap volume to uid 1000, the user of both services that mount it", () => {
    // Integration brief item 11: sealed-agent creates the volume with this owner, so no service
    // has to start as root to make it writable.
    const owners = volumeOwners(app.fragment);
    assert.equal(owners.get("internal-tools-bootstrap"), "1000:1000");
    for (const [name, svc] of Object.entries(services)) {
      for (const mount of svc.volumes ?? []) {
        if (mount.startsWith("internal-tools-bootstrap:")) assert.equal(svc.user, "1000:1000", name);
      }
    }
    assert.equal(services["internal-tools-bootstrap"].volumes[0], "internal-tools-bootstrap:/sealed-bootstrap");
    assert.equal(services["internal-tools-server"].volumes[0], "internal-tools-bootstrap:/sealed-bootstrap:ro");
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

  test("the database init script creates a non-superuser sample role and closes ToolJet's databases to PUBLIC", () => {
    const script = unescapeFromCompose(services["internal-tools-db"].entrypoint[2]);
    assert.match(script, /CREATE ROLE tooljet_sample LOGIN CREATEDB PASSWORD :'pw';/);
    assert.match(script, /REVOKE CONNECT, TEMPORARY ON DATABASE tooljet_production, tooljet_db FROM PUBLIC;/);
    assert.equal(services["internal-tools-server"].environment.PG_DB, "tooljet_production");
    assert.equal(services["internal-tools-server"].environment.TOOLJET_DB, "tooljet_db");
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

  test("valkey gets its password from a tmpfs config file, never from argv", async () => {
    const svc = services["internal-tools-valkey"];
    const script = unescapeFromCompose(svc.entrypoint[2]);
    assert.deepEqual(svc.tmpfs, ["/run/valkey"]);
    assert.doesNotMatch(script, /--requirepass/);
    assert.match(svc.healthcheck.test[1], /^VALKEYCLI_AUTH="\$\$\(cat \/run\/sealed\/secrets\/internal-tools\/REDIS_PASSWORD\)" valkey-cli ping/);
    const dir = await mkdtemp(join(tmpdir(), "tools-valkey-"));
    try {
      const bin = join(dir, "bin");
      await mkdir(bin);
      await writeFile(join(bin, "chown"), "#!/bin/sh\nexit 0\n");
      await writeFile(join(bin, "tini"), `#!/bin/sh\nshift\nprintf '%s\\n' "$@" > "${dir}/argv"\nenv > "${dir}/env"\n`);
      await chmod(join(bin, "chown"), 0o755);
      await chmod(join(bin, "tini"), 0o755);
      const conf = join(dir, "valkey.conf");
      const res = spawnSync("/bin/sh", ["-c", script.replaceAll("/run/valkey/valkey.conf", conf), "internal-tools-valkey", ...svc.command], {
        env: { PATH: `${bin}:${process.env.PATH}`, REDIS_PASSWORD: "feedface".repeat(8) },
        encoding: "utf8",
      });
      assert.equal(res.status, 0, res.stderr);
      const argv = (await readFile(join(dir, "argv"), "utf8")).trim().split("\n");
      assert.deepEqual(argv, ["docker-entrypoint.sh", "valkey-server", conf, "--maxmemory-policy", "noeviction", "--appendonly", "yes"]);
      assert.equal(await readFile(conf, "utf8"), `requirepass "${"feedface".repeat(8)}"\n`);
      assert.equal((await stat(conf)).mode & 0o777, 0o600);
      assert.doesNotMatch(await readFile(join(dir, "env"), "utf8"), /REDIS_PASSWORD/);
    } finally {
      await rm(dir, { recursive: true, force: true });
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

});

describe("egress, waivers, licenses and docs", () => {
  test("egress allows nothing by default and accepts customer additions", () => {
    assert.deepEqual(app.egress.default_allow, []);
    assert.equal(app.egress.customer_additions_allowed, true);
  });

  test("waivers file is well formed", () => {
    assert.deepEqual(checkWaivers(app.waivers, app.manifest), []);
  });

  test("ships the upstream license texts named in LICENSE-NOTICE", async () => {
    const notice = await readFile(join(appDir, "LICENSE-NOTICE"), "utf8");
    const files = notice.match(/LICENSES\/[\w.-]+/g);
    assert.equal(files.length, 4);
    for (const file of files) assert.ok((await readFile(join(appDir, file), "utf8")).length > 500, file);
    assert.match(await readFile(join(appDir, "LICENSES/tooljet-v3.20.251-lts-LICENSE"), "utf8"), /GNU AFFERO GENERAL PUBLIC LICENSE/);
    assert.match(notice, /https:\/\/github\.com\/ToolJet\/ToolJet\/tree\/v3\.20\.251-lts/);
  });

  test("each license text is byte for byte the upstream file LICENSE-NOTICE names (git blob)", async () => {
    // License audit F10: the texts were compared with upstream by git blob hash; keep it that way.
    const notice = await readFile(join(appDir, "LICENSE-NOTICE"), "utf8");
    const entries = [...notice.matchAll(/LICENSES\/([\w.-]+)\s*\n\s*\(([\w.-]+\/[\w.-]+) (\S+) (\S+), git blob ([0-9a-f]{40})\)/g)];
    assert.deepEqual(Object.fromEntries(entries.map((m) => [m[1], `${m[2]} ${m[3]} ${m[4]}`])), {
      "tooljet-v3.20.251-lts-LICENSE": "ToolJet/ToolJet v3.20.251-lts LICENSE",
      "postgrest-v12.2.12-LICENSE": "PostgREST/postgrest v12.2.12 LICENSE",
      "postgresql-16.15-COPYRIGHT": "postgres/postgres REL_16_15 COPYRIGHT",
      "valkey-9.0.7-COPYING": "valkey-io/valkey 9.0.7 COPYING",
    });
    const blob = (data) => createHash("sha1").update(Buffer.concat([Buffer.from(`blob ${data.length}\0`), data])).digest("hex");
    assert.equal(blob(Buffer.from("hello\n")), "ce013625030ba8dba906f756967f9e9ca394464a"); // git hash-object
    for (const [, file, , , , sha] of entries) assert.equal(blob(readFileSync(join(appDir, "LICENSES", file))), sha, file);
    const present = readdirSync(join(appDir, "LICENSES")).filter((n) => !n.startsWith(".")).sort();
    assert.deepEqual(entries.map((m) => m[1]).sort(), present);
  });

  test("docs and manifest text contain no em-dashes", async () => {
    for (const file of ["README.md", "LICENSE-NOTICE", "manifest.yaml", "egress.yaml", "compose.fragment.yaml", "images/tooljet-ce/Dockerfile"]) {
      assert.ok(!(await readFile(join(appDir, file), "utf8")).includes("\u2014"), `${file} has an em-dash`);
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

const composer = findComposer(appDir);
const brief = composer.brief ? false : `composer ${composer.version} predates integration brief items 5 to 11 (1.2.0)`;
describe("the real composer (runtime/composer)", { skip: composer.skip }, () => {
  test("sealed-compose lint blocks the release only on the unbuilt ToolJet image (D-028)", () => {
    const findings = composerLint(composer, appDir);
    assert.deepEqual(unexpectedFindings(findings), [], "only the unbuilt image and the SBOMs CI generates");
    const errors = findings.filter((f) => f.severity === "error").map((f) => `${f.code} ${f.field ?? ""}`.trim());
    const tooljet = app.manifest.images.findIndex((i) => i.name === "tooljet");
    const unbuilt = /^sha256:0{64}$/.test(app.manifest.images[tooljet].digest);
    // Until the runtime image workflow builds images/tooljet-ce and its digest is pinned, the
    // composer refuses the release. Any other error means this app drifted from its rules.
    assert.deepEqual(errors, unbuilt ? [`unbuilt-image images[${tooljet}].digest`] : []);
  });

  describe("composed stack", async () => {
    const out = await mkdtemp(join(tmpdir(), "tools-composed-"));
    after(() => rm(out, { recursive: true, force: true }));
    const stack = composeStack(composer, [appDir], out);
    const composed = stack.compose.services;
    const site = caddySite(stack.caddyfile, "tools.34-1-2-3.sslip.io");

    test("the tools route goes to the route port, never to the setup port", () => {
      assert.match(site, /reverse_proxy internal-tools-server:3000/);
      assert.doesNotMatch(stack.caddyfile, /internal-tools-server:3001/);
    });

    test("the tools route is gated by sealed-agent (forward_auth), not by Caddy basic_auth", { skip: brief }, () => {
      assert.match(site, /forward_auth sealed-agent:7070/);
      assert.match(site, /\/v1\/gate\?route=tools/);
      assert.doesNotMatch(site, /basic_auth/);
    });

    test("internal-tools-server sees done.json read-only and keeps the fragment's healthcheck", () => {
      const server = composed["internal-tools-server"];
      const mount = server.volumes.find((v) => v.target === "/sealed-bootstrap");
      assert.equal(mount.source, "/mnt/sealed-data/internal-tools/internal-tools-bootstrap");
      assert.equal(mount.read_only, true);
      assert.deepEqual(server.healthcheck.test, services["internal-tools-server"].healthcheck.test);
      assert.equal(composed["internal-tools-bootstrap"].restart, "on-failure");
      const tools = stack.stack.apps.find((a) => a.id === "internal-tools");
      assert.equal(tools.bootstrap.doneFile, "internal-tools-bootstrap/done.json");
      assert.equal(tools.bootstrap.donePath, "/mnt/sealed-data/internal-tools/internal-tools-bootstrap/done.json");
    });

    test("each service exports exactly the secrets it lists", () => {
      for (const [name, svc] of Object.entries(services)) {
        assert.deepEqual([...envexecSecrets(composed[name])].sort(), [...(svc["x-sealed-secrets"] ?? [])].sort(), name);
      }
    });

    test("each service gets bind mounts of exactly the secret files it lists", { skip: brief }, () => {
      const root = "/run/sealed/secrets/internal-tools";
      for (const [name, svc] of Object.entries(services)) {
        const want = (svc["x-sealed-secrets"] ?? []).map((s) => `${root}/${s}`).sort();
        assert.deepEqual([...secretMounts(composed[name], "internal-tools")].sort(), want, name);
      }
    });

    test("the bootstrap volume's owner is recorded for sealed-agent", { skip: brief }, () => {
      const tools = stack.stack.apps.find((a) => a.id === "internal-tools");
      const entry = tools.volumes.find((v) => v.name === "internal-tools-bootstrap");
      assert.ok(JSON.stringify(entry).includes('"1000:1000"'), JSON.stringify(entry));
    });

    // The ":?" guard in the entrypoints stops internal-tools-server and internal-tools-bootstrap
    // when the composer does not set SEALED_PUBLIC_URL_TOOLS.
    test("the composer sets SEALED_PUBLIC_URL_TOOLS on every internal-tools service", { skip: brief }, () => {
      for (const name of Object.keys(services)) {
        assert.equal(composed[name].environment.SEALED_PUBLIC_URL_TOOLS, "https://tools.34-1-2-3.sslip.io", name);
      }
    });

    test("only internal-tools-server joins the shared apps network (D-041)", { skip: brief }, () => {
      for (const name of Object.keys(services)) {
        const networks = Object.keys(composed[name].networks);
        assert.ok(networks.includes("app-internal-tools"), name);
        assert.equal(networks.includes("apps"), name === "internal-tools-server", name);
      }
    });

    test("valkey's password stays out of the composed argv", () => {
      const valkey = composed["internal-tools-valkey"];
      assert.ok(!JSON.stringify([valkey.entrypoint, valkey.command]).includes("--requirepass"));
    });

    test("docker compose accepts the composed document", { skip: !dockerComposeAvailable() && "docker compose not installed" }, () => {
      const result = composeConfig(stack.composePath, "sealed-tools-composed");
      assert.ok(result.ok, result.stderr);
    });
  });
});
