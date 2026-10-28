// Runs the real composer (runtime/composer/cmd/sealed-compose) for the internal-tools tests.
//
// The app-local copy of the catalog rules is gone (integration brief item 25): the manifest, the
// fragment and the egress policy are checked only by `go run ./runtime/composer/cmd/sealed-compose
// lint`, and composed stacks come from `sealed-compose compose`. Switch to catalog/tools/ once that
// shared tooling exists.
//
// The app already uses fields from integration brief items 5 to 11 (the `password` generator and
// `x-sealed-owner` on volumes) that composer 1.2.0 introduces. With an older composer in the tree,
// inputs() hands the composer a copy of the app without exactly those fields, so every other rule
// still runs; tests of 1.2.0 behaviour check `composer.brief` and skip with the reason otherwise.
//
// The composer is looked up in SEALED_COMPOSER_DIR, then in this checkout. Without Go or the
// composer source the tests skip, unless CI or SEALED_REQUIRE_COMPOSER=1 is set; then they fail.

import { spawnSync } from "node:child_process";
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { parse, parseDocument } from "yaml";

export const BRIEF_VERSION = [1, 2, 0];
export const REGISTRY = "ghcr.io/sealedtempo";
const CLI = "./runtime/composer/cmd/sealed-compose";

function required() {
  return process.env.SEALED_REQUIRE_COMPOSER === "1" || Boolean(process.env.CI);
}

function versionTuple(text) {
  return (text.match(/\d+/g) ?? []).slice(0, 3).map(Number);
}

function atLeast(a, b) {
  for (let i = 0; i < b.length; i++) {
    if ((a[i] ?? 0) !== b[i]) return (a[i] ?? 0) > b[i];
  }
  return true;
}

// The composer for appDir, or {skip} with the reason it cannot run. Throws under CI or
// SEALED_REQUIRE_COMPOSER=1 instead of skipping.
export function findComposer(appDir) {
  let reason;
  const dir = resolve(process.env.SEALED_COMPOSER_DIR || resolve(appDir, "../../.."));
  if (spawnSync("go", ["version"], { encoding: "utf8" }).status !== 0) reason = "go is not installed";
  else if (!existsSync(join(dir, CLI, "main.go"))) reason = `composer source not found under ${dir} (set SEALED_COMPOSER_DIR)`;
  if (reason) {
    if (required()) throw new Error(`the real composer is required here: ${reason}`);
    return { skip: reason };
  }
  const version = composerVersion(dir);
  return { dir, version, brief: atLeast(versionTuple(version), BRIEF_VERSION) };
}

// The composer's own version (const Version in runtime/composer), which a config must name.
export function composerVersion(dir) {
  const src = join(dir, "runtime/composer");
  for (const file of readdirSync(src).sort()) {
    if (!file.endsWith(".go") || file.endsWith("_test.go")) continue;
    const m = /^const Version = "([^"]+)"/m.exec(readFileSync(join(src, file), "utf8"));
    if (m) return m[1];
  }
  throw new Error("cannot find the composer version");
}

function runComposer(composer, args) {
  const res = spawnSync("go", ["run", CLI, ...args], { cwd: composer.dir, encoding: "utf8", timeout: 600_000 });
  return { status: res.status, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

// A copy of the composer's input files of an app, without the brief-only fields: manifest
// secrets[].same_as, fragment volumes.<name>.x-sealed-owner, and generate: password (which
// becomes generate: none). Comments and every other value stay as they are.
export function briefCompatibleCopy(appDir, destRoot) {
  const manifest = parseDocument(readFileSync(join(appDir, "manifest.yaml"), "utf8"));
  const fragment = parseDocument(readFileSync(join(appDir, "compose.fragment.yaml"), "utf8"));
  const id = manifest.get("id");
  const dest = join(mkdtempSync(join(destRoot, `${id}-`)), id);
  mkdirSync(dest);
  for (const secret of manifest.get("secrets")?.items ?? []) {
    secret.delete("same_as");
    if (secret.get("generate") === "password") secret.set("generate", "none");
  }
  for (const pair of fragment.get("volumes")?.items ?? []) {
    if (pair.value?.delete) pair.value.delete("x-sealed-owner");
  }
  writeFileSync(join(dest, "manifest.yaml"), manifest.toString({ lineWidth: 0 }));
  writeFileSync(join(dest, "compose.fragment.yaml"), fragment.toString({ lineWidth: 0 }));
  for (const name of ["egress.yaml", "LICENSE-NOTICE", "README.md"]) {
    if (existsSync(join(appDir, name))) copyFileSync(join(appDir, name), join(dest, name));
  }
  if (existsSync(join(appDir, "LICENSES"))) cpSync(join(appDir, "LICENSES"), join(dest, "LICENSES"), { recursive: true });
  return dest;
}

// The directories to hand to the composer (see briefCompatibleCopy) and a cleanup function.
function inputs(composer, appDirs) {
  if (composer.brief) return { dirs: appDirs.map((d) => resolve(d)), done: () => {} };
  const scratch = mkdtempSync(join(tmpdir(), "sealed-brief-compat-"));
  return { dirs: appDirs.map((d) => briefCompatibleCopy(d, scratch)), done: () => rmSync(scratch, { recursive: true, force: true }) };
}

// sealed-compose lint --json: the findings, whatever the exit code.
export function composerLint(composer, appDir) {
  const { dirs, done } = inputs(composer, [appDir]);
  try {
    const res = runComposer(composer, ["lint", "--json", ...dirs.flatMap((d) => ["--app-dir", d])]);
    try {
      return JSON.parse(res.stdout);
    } catch {
      throw new Error(`sealed-compose lint failed: ${res.stderr}`);
    }
  } finally {
    done();
  }
}

// sealed-compose lint --json of a copy of the app that carries a made-up SPDX SBOM for one image
// (sbom/<image>.spdx.json) with the given package names (license MIT) and file paths. Returns the
// excluded-path findings as a Map from SBOM entry (name@1.0.0 or file path) to the patterns it hit.
export function excludedPathHits(composer, appDir, image, { packages = [], files = [] }) {
  const scratch = mkdtempSync(join(tmpdir(), "sealed-sbom-"));
  try {
    const dir = briefCompatibleCopy(appDir, scratch);
    mkdirSync(join(dir, "sbom"));
    writeFileSync(join(dir, "sbom", `${image}.spdx.json`), JSON.stringify({
      spdxVersion: "SPDX-2.3",
      SPDXID: "SPDXRef-DOCUMENT",
      name: image,
      packages: packages.map((name) => ({ name, versionInfo: "1.0.0", licenseConcluded: "MIT" })),
      files: files.map((fileName) => ({ fileName })),
    }));
    const res = runComposer(composer, ["lint", "--json", "--app-dir", dir]);
    let findings;
    try {
      findings = JSON.parse(res.stdout);
    } catch {
      throw new Error(`sealed-compose lint failed: ${res.stderr}`);
    }
    return excludedHits(findings, files);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

// excluded-path findings of `lint --json` as a Map from SBOM entry to the patterns it hit. The lint
// (license audit F6 globs) reports a package by name@version, a matched file by its path, and the
// files under a matched directory once, by the directory ("/<dir>/", every pattern that matched it in
// the message); each of `files` under a reported directory gets that directory's patterns.
export function excludedHits(findings, files = []) {
  const hits = new Map();
  for (const f of findings.filter((x) => x.code === "excluded-path")) {
    const list = /excluded paths? ((?:"[^"]*"(?:, )?)+)/.exec(f.message)?.[1];
    const patterns = list ? [...list.matchAll(/"([^"]*)"/g)].map((m) => m[1]) : [""];
    const set = hits.get(f.field ?? "") ?? new Set();
    for (const p of patterns) set.add(p);
    hits.set(f.field ?? "", set);
  }
  for (const path of files) {
    for (const [field, patterns] of [...hits]) {
      if (!field.endsWith("/") || !path.startsWith(field)) continue;
      const set = hits.get(path) ?? new Set();
      for (const p of patterns) set.add(p);
      hits.set(path, set);
    }
  }
  return hits;
}

// Findings other than the allowed error and warning codes, as readable lines.
export function unexpectedFindings(findings, { errors = ["unbuilt-image"], warnings = ["sbom-missing"] } = {}) {
  const allowed = { error: new Set(errors), warning: new Set(warnings) };
  return findings
    .filter((f) => !allowed[f.severity]?.has(f.code))
    .map((f) => `${f.severity} ${f.file ?? ""} ${f.field ?? ""} [${f.code}] ${f.message}`);
}

export function sampleConfig(appIds, version, { brief = true } = {}) {
  const word = (byte, len) => `0x${byte.repeat(len)}`;
  const config = {
    schema: "sealed-config/v1",
    chainId: 4217,
    customer: word("0", 38) + "c1",
    salt: word("5a", 32),
    imageId: word("1d", 32),
    composerVersion: version,
    apps: [...appIds].sort().map((id) => ({ id, releaseId: word("00", 32) })),
    hostnames: { scheme: "sslip", ip: "34.1.2.3" },
    egressAdditions: {},
    allowedVpcRanges: [],
    endpoints: {
      keyBroker: "https://sealed-key-broker-xyz.a.run.app",
      platformApi: "https://api.sealed.example",
      tempoRpc: "https://rpc.tempo.xyz",
      // The relay is served on its deployment's attest host (D-045).
      relay: "https://attest.relay.sealed.example",
      relayAttest: "https://attest.relay.sealed.example/attest",
    },
    contracts: {
      platformRegistry: word("0", 38) + "e1",
      appRegistry: word("0", 38) + "e2",
      deploymentRegistry: word("0", 38) + "e3",
      feeSplitter: word("0", 38) + "e4",
    },
    feeToken: "0x20c000000000000000000000b9537d11c60e8b50",
    settlement: { mode: "access-key", intervalMinutes: 60, gracePeriodMinutes: 1440, spendLimitPerDay: "2000000" },
    relayOwner: word("0", 38) + "b1",
  };
  if (brief) config.debug = false; // integration brief item 13, composer 1.2.0
  return config;
}

// sealed-compose compose for the given app directories into outDir. Returns the artifacts.
export function composeStack(composer, appDirs, outDir) {
  mkdirSync(outDir, { recursive: true });
  const ids = appDirs.map((d) => parse(readFileSync(join(d, "manifest.yaml"), "utf8")).id);
  const configPath = join(outDir, "input-config.json");
  writeFileSync(configPath, JSON.stringify(sampleConfig(ids, composer.version, { brief: composer.brief })));
  const { dirs, done } = inputs(composer, appDirs);
  try {
    const args = ["compose", "--config", configPath, "--fill-release-ids", "--allow-missing-sbom", "--registry", REGISTRY];
    for (const d of dirs) args.push("--app-dir", d);
    args.push("--out", outDir);
    const res = runComposer(composer, args);
    if (res.status !== 0) throw new Error(`sealed-compose compose failed: ${res.stderr}`);
  } finally {
    done();
  }
  const read = (name) => readFileSync(join(outDir, name), "utf8");
  return {
    caddyfile: read("Caddyfile"),
    caddyfilePaymentNeeded: read("Caddyfile.payment-needed"),
    compose: JSON.parse(read("docker-compose.json")),
    composePath: join(outDir, "docker-compose.json"),
    stack: JSON.parse(read("stack.json")),
  };
}

// The block of one site ("<host> {" to the "}" at column 0) in a rendered Caddyfile.
export function caddySite(caddyfile, host) {
  const lines = caddyfile.split("\n");
  const start = lines.indexOf(`${host} {`);
  if (start < 0) return undefined;
  const end = lines.findIndex((l, i) => i > start && l === "}");
  return lines.slice(start, end + 1).join("\n");
}

// Targets of a composed service's mounts under /run/sealed/secrets/<appId>.
export function secretMounts(service, appId) {
  const root = `/run/sealed/secrets/${appId}`;
  return new Set(
    (service.volumes ?? [])
      .map((v) => (typeof v === "string" ? v.split(":")[1] : v.target))
      .filter((t) => t === root || t?.startsWith(`${root}/`)),
  );
}

// Secret names a composed service's envexec entrypoint exports (--secret / --optional-secret).
export function envexecSecrets(service) {
  const entry = service.entrypoint;
  const sep = entry.indexOf("--");
  const names = new Set();
  for (let i = 0; i < sep; i++) if (entry[i] === "--secret" || entry[i] === "--optional-secret") names.add(entry[i + 1]);
  return names;
}
