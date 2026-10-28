// Tests for the shared catalog tooling. They run the real composer, so Go (or SEALED_COMPOSE_BIN)
// is needed; with SEALED_REQUIRE_COMPOSER=1 a missing composer fails instead of skipping.
//   node --test catalog/tools/*.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  caddyHandles,
  caddySite,
  composeConfig,
  composeStack,
  composerLint,
  composerVersion,
  dockerComposeAvailable,
  errorsOf,
  findComposer,
  gateRoute,
  memMiB,
  REPO_ROOT,
  sampleConfig,
} from "./catalog-lint.mjs";

const fixtures = join(REPO_ROOT, "runtime/composer/testdata/apps");
const composer = findComposer();
if (composer.skip && process.env.SEALED_REQUIRE_COMPOSER === "1") throw new Error(composer.skip);
const skip = composer.skip ? { skip: composer.skip } : {};
const work = mkdtempSync(join(tmpdir(), "catalog-tools-"));
after(() => rmSync(work, { recursive: true, force: true }));

function copyFixture(app) {
  const dir = join(mkdtempSync(join(work, "app-")), app);
  cpSync(join(fixtures, app), dir, { recursive: true });
  return dir;
}

describe("composer lint wrapper", skip, () => {
  test("clean fixtures have no errors, even in release mode", () => {
    for (const app of ["notes", "llm-gateway", "inference-relay"]) {
      assert.deepEqual(errorsOf(composerLint(composer, join(fixtures, app), { requireSbom: true })), [], app);
    }
  });

  test("findings come back as the composer reports them", () => {
    const dir = copyFixture("notes");
    const manifest = join(dir, "manifest.yaml");
    writeFileSync(manifest, readFileSync(manifest, "utf8").replace("license_spdx: PostgreSQL", "license_spdx: SSPL-1.0"));
    writeFileSync(join(dir, "waivers.yaml"), "- {id: CVE-2020-1234, image: postgres, package: x, reason: old finding here, expires: 2020-01-01}\n");
    const errors = errorsOf(composerLint(composer, dir));
    assert.ok(errors.some((f) => f.code === "license" && f.field === "images[1].license_spdx"), JSON.stringify(errors));
    assert.ok(errors.some((f) => f.code === "waivers" && /expired/.test(f.message)), JSON.stringify(errors));
    for (const f of errors) assert.deepEqual(Object.keys(f).sort().filter((k) => !["file", "field"].includes(k)), ["app", "code", "message", "severity"]);
  });

  test("release mode: missing license metadata and enterprise paths in the SBOM file list", () => {
    // License audit F5 and F6: a package without license metadata is an error in release mode
    // unless a reviewed override covers it (map-stream 0.1.0 is covered), and the ee/ default
    // matches the file list as a path segment.
    const dir = copyFixture("notes");
    const pkg = (name, version) => ({
      SPDXID: `SPDXRef-${name}`, name, versionInfo: version, licenseConcluded: "NOASSERTION", licenseDeclared: "NOASSERTION",
      externalRefs: [{ referenceType: "purl", referenceLocator: `pkg:npm/${name}@${version}` }],
    });
    const sbom = {
      spdxVersion: "SPDX-2.3",
      name: "notes-web",
      packages: [pkg("map-stream", "0.1.0"), pkg("left-pad", "1.3.0")],
      files: [
        { SPDXID: "SPDXRef-f1", fileName: "app/server/ee/licensing/license.service.js" },
        { SPDXID: "SPDXRef-f2", fileName: "app/server/tree/index.js" },
      ],
    };
    writeFileSync(join(dir, "sbom", "notes-web.spdx.json"), JSON.stringify(sbom));
    const release = errorsOf(composerLint(composer, dir, { requireSbom: true }));
    assert.deepEqual(release.filter((f) => f.code === "sbom-no-license").map((f) => f.field), ["left-pad@1.3.0"], JSON.stringify(release));
    assert.deepEqual(release.filter((f) => f.code === "excluded-path").map((f) => f.field), ["/app/server/ee/"], JSON.stringify(release));
    const dev = composerLint(composer, dir);
    assert.ok(dev.some((f) => f.code === "sbom-no-license" && f.severity === "warning" && f.field === "left-pad@1.3.0"), JSON.stringify(dev));
    assert.ok(!errorsOf(dev).some((f) => f.code === "sbom-no-license"));
  });

  test("the CLI exits 1 on errors and 0 when clean", () => {
    const cli = fileURLToPath(new URL("./catalog-lint.mjs", import.meta.url));
    const env = { ...process.env, SEALED_COMPOSE_BIN: composer.bin };
    const clean = spawnSync(process.execPath, [cli, "--json", join(fixtures, "notes")], { encoding: "utf8", env });
    assert.equal(clean.status, 0, clean.stderr);
    assert.ok(Array.isArray(JSON.parse(clean.stdout)));
    const dir = copyFixture("notes");
    writeFileSync(join(dir, "egress.yaml"), "version: 1\ndefault_allow: [\"169.254.169.254:80\"]\ncustomer_additions_allowed: false\n");
    const bad = spawnSync(process.execPath, [cli, "--app-dir", dir], { encoding: "utf8", env });
    assert.equal(bad.status, 1);
    assert.match(bad.stdout, /^error: notes\/egress\.yaml \[egress\]/m);
    assert.equal(spawnSync(process.execPath, [cli], { encoding: "utf8", env }).status, 2);
  });
});

describe("compose helpers", skip, () => {
  test("sampleConfig names the composer version and the relay attest origin", () => {
    const cfg = sampleConfig(["notes", "llm-gateway"], composerVersion(composer));
    // The composer's own Version constant, so a version bump needs no edit here.
    const goVersion = /const Version = "([^"]+)"/.exec(readFileSync(join(REPO_ROOT, "runtime/composer/runtimeimages.go"), "utf8"))?.[1];
    assert.ok(goVersion);
    assert.equal(cfg.composerVersion, goVersion);
    assert.deepEqual(cfg.apps.map((a) => a.id), ["llm-gateway", "notes"]);
    assert.equal(new URL(cfg.endpoints.relayAttest).origin, cfg.endpoints.relay);
  });

  test("composeStack returns the composed artifacts with app networks and the forward_auth gate", () => {
    const out = join(work, "stack");
    const stack = composeStack(composer, [join(fixtures, "notes"), join(fixtures, "llm-gateway")], out);
    assert.equal(stack.stack.schema, "sealed-stack/v1");
    assert.equal(stack.config.debug, false);
    const web = stack.compose.services["notes-web"];
    assert.deepEqual(Object.keys(web.networks).sort(), ["app-notes", "apps"]);
    assert.deepEqual(Object.keys(stack.compose.services["notes-db"].networks), ["app-notes"]);
    assert.equal(web.environment.SEALED_PUBLIC_URL_TOOLS, "https://tools.34-1-2-3.sslip.io");
    const handles = caddyHandles(caddySite(stack.caddyfile, "tools.34-1-2-3.sslip.io"));
    assert.equal(gateRoute(handles[""]), "tools");
    const gw = caddyHandles(caddySite(stack.caddyfile, "gateway.34-1-2-3.sslip.io"));
    assert.equal(gateRoute(gw["@r1_bearer"]), undefined);
    assert.equal(gateRoute(gw["@r0"]), "gateway");
    assert.equal(caddySite(stack.caddyfile, "crm.34-1-2-3.sslip.io"), undefined);
  });

  test("composed output passes docker compose config", { skip: !dockerComposeAvailable() && "docker compose CLI not installed" }, () => {
    const out = join(work, "stack-docker");
    const stack = composeStack(composer, [join(fixtures, "inference-relay")], out, { config: { debug: true } });
    assert.equal(stack.compose.services["inference-relay-front"].logging.driver, "local");
    const res = composeConfig(stack.composePath);
    assert.ok(res.ok, res.stderr);
  });
});

test("memMiB", () => {
  assert.equal(memMiB("2g"), 2048);
  assert.equal(memMiB("512m"), 512);
  assert.equal(memMiB("1024k"), 1);
  assert.throws(() => memMiB("lots"));
});
