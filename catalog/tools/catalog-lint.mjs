#!/usr/bin/env node
// Shared catalog tooling (integration brief item 25): a thin wrapper around the composer's lint and
// compose commands (runtime/composer/cmd/sealed-compose), which are the only authority for the
// catalog rules. App test suites import it instead of keeping their own copies of the rules.
// No dependencies: Node 22+ built-ins only.
//
//   node catalog/tools/catalog-lint.mjs [--json] [--require-sbom] [--registry R] (--catalog DIR | --app-dir DIR...)
//
// The composer binary comes from SEALED_COMPOSE_BIN, or is built once per process from the Go
// sources of this checkout (or SEALED_COMPOSER_DIR) with `go build`.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const DEFAULT_REGISTRY = "ghcr.io/sealedtempo";
const COMPOSER_MAIN = "runtime/composer/cmd/sealed-compose";

let built;

/**
 * Locates the composer. Returns {bin} ready to run, or {skip: reason} when neither SEALED_COMPOSE_BIN
 * nor Go with the composer sources is available.
 */
export function findComposer() {
  if (process.env.SEALED_COMPOSE_BIN) {
    const bin = resolve(process.env.SEALED_COMPOSE_BIN);
    return existsSync(bin) ? { bin } : { skip: `SEALED_COMPOSE_BIN ${bin} does not exist` };
  }
  if (built) return built;
  const dirs = [process.env.SEALED_COMPOSER_DIR, REPO_ROOT].filter(Boolean);
  const dir = dirs.find((d) => existsSync(join(d, COMPOSER_MAIN, "main.go")));
  if (!dir) return { skip: "composer sources not found (set SEALED_COMPOSE_BIN or SEALED_COMPOSER_DIR)" };
  if (spawnSync("go", ["version"], { encoding: "utf8" }).status !== 0) return { skip: "go is not installed" };
  const tmp = mkdtempSync(join(tmpdir(), "sealed-compose-"));
  process.on("exit", () => rmSync(tmp, { recursive: true, force: true }));
  const out = join(tmp, "sealed-compose");
  const res = spawnSync("go", ["build", "-o", out, `./${COMPOSER_MAIN}`], { cwd: dir, encoding: "utf8", timeout: 600_000 });
  if (res.status !== 0) throw new Error(`building sealed-compose failed: ${res.stderr}`);
  built = { bin: out, dir };
  return built;
}

/** Runs sealed-compose with the given arguments. */
export function runCompose(composer, args, options = {}) {
  if (!composer?.bin) throw new Error(`composer unavailable: ${composer?.skip ?? "not found"}`);
  const res = spawnSync(composer.bin, args, { encoding: "utf8", timeout: 600_000, cwd: REPO_ROOT, ...options });
  return { status: res.status, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

/** The composer's version, which a config's composerVersion must equal. */
export function composerVersion(composer) {
  const res = runCompose(composer, ["version"]);
  if (res.status !== 0) throw new Error(`sealed-compose version failed: ${res.stderr}`);
  return res.stdout.trim();
}

/**
 * sealed-compose lint --json for one or more app directories (or {catalog: dir}). Returns the
 * findings whatever the exit code: [{severity, app, file, field, code, message}].
 */
export function composerLint(composer, target, { requireSbom = false, registry } = {}) {
  const args = ["lint", "--json"];
  if (requireSbom) args.push("--require-sbom");
  if (registry) args.push("--registry", registry);
  if (typeof target === "string") args.push("--app-dir", resolve(target));
  else if (Array.isArray(target)) for (const d of target) args.push("--app-dir", resolve(d));
  else if (target?.catalog) args.push("--catalog", resolve(target.catalog));
  else throw new Error("composerLint: pass an app dir, a list of app dirs or {catalog}");
  const res = runCompose(composer, args);
  try {
    return JSON.parse(res.stdout);
  } catch {
    throw new Error(`sealed-compose lint failed: ${res.stderr}`);
  }
}

export const errorsOf = (findings) => findings.filter((f) => f.severity === "error");

/** A public config (sealed-config/v1) for local composes; releaseIds are filled from the bundles. */
export function sampleConfig(appIds, version, overrides = {}) {
  const word = (byte, len) => `0x${byte.repeat(len)}`;
  return {
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
      // endpoints.relay is the relay deployment's attest origin (D-045).
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
    debug: false,
    ...overrides,
  };
}

/**
 * Composes a stack from app directories into outDir with the real composer (development
 * releaseIds, SBOMs optional) and returns every artifact, parsed where it is JSON.
 * App ids are the directory names (catalog lint requires id == directory).
 */
export function composeStack(composer, appDirs, outDir, { registry = DEFAULT_REGISTRY, config = {} } = {}) {
  mkdirSync(outDir, { recursive: true });
  const ids = appDirs.map((d) => basename(resolve(d)));
  const configPath = join(outDir, "input-config.json");
  writeFileSync(configPath, JSON.stringify(sampleConfig(ids, composerVersion(composer), config)));
  const args = ["compose", "--config", configPath, "--fill-release-ids", "--allow-missing-sbom", "--registry", registry];
  for (const d of appDirs) args.push("--app-dir", resolve(d));
  args.push("--out", outDir);
  const res = runCompose(composer, args);
  if (res.status !== 0) throw new Error(`sealed-compose compose failed: ${res.stderr}`);
  const read = (name) => readFileSync(join(outDir, name), "utf8");
  return {
    appCompose: read("app-compose.json"),
    caddyfile: read("Caddyfile"),
    caddyfilePaymentNeeded: read("Caddyfile.payment-needed"),
    compose: JSON.parse(read("docker-compose.json")),
    composePath: join(outDir, "docker-compose.json"),
    stack: JSON.parse(read("stack.json")),
    egress: JSON.parse(read("egress.json")),
    config: JSON.parse(read("config.json")),
  };
}

/** The block of one site ("<host> {" to the "}" at column 0) in a rendered Caddyfile. */
export function caddySite(caddyfile, host) {
  const lines = caddyfile.split("\n");
  const start = lines.indexOf(`${host} {`);
  if (start < 0) return undefined;
  const end = lines.findIndex((l, i) => i > start && l === "}");
  return lines.slice(start, end + 1).join("\n");
}

/** The handle blocks of a site, keyed by their matcher ("" for the catch-all handle). */
export function caddyHandles(site) {
  const handles = {};
  const lines = site.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^\thandle(?: (@\S+))? \{$/.exec(lines[i]);
    if (!m) continue;
    const end = lines.findIndex((l, j) => j > i && l === "\t}");
    handles[m[1] ?? ""] = lines.slice(i + 1, end).join("\n");
    i = end;
  }
  return handles;
}

/** Whether a handle body asks sealed-agent's gate (D-044), and for which route. */
export function gateRoute(handle) {
  const m = /forward_auth sealed-agent:7070 \{\n\t+uri \/v1\/gate\?route=([a-z0-9-]+)\n/.exec(handle ?? "");
  return m ? m[1] : undefined;
}

/** Parses a compose memory value ("2g", "512m", "1024k") into MiB. */
export function memMiB(value) {
  const m = /^(\d+(?:\.\d+)?)([kmg])b?$/i.exec(String(value).trim());
  if (!m) throw new Error(`cannot read mem_limit ${value}`);
  const n = Number(m[1]);
  return { k: n / 1024, m: n, g: n * 1024 }[m[2].toLowerCase()];
}

export function dockerComposeAvailable() {
  return spawnSync("docker", ["compose", "version"], { encoding: "utf8" }).status === 0;
}

/** docker compose config on a file; needs only the CLI and the compose plugin, no daemon. */
export function composeConfig(file, project = "sealed") {
  const res = spawnSync("docker", ["compose", "-p", project, "-f", file, "config", "--format", "json"], {
    encoding: "utf8",
    env: { ...process.env, DOCKER_HOST: process.env.DOCKER_HOST ?? "unix:///nonexistent.sock" },
  });
  if (res.status !== 0) return { ok: false, stderr: res.stderr };
  return { ok: true, config: JSON.parse(res.stdout) };
}

export function dockerDaemonAvailable() {
  return spawnSync("docker", ["info", "--format", "{{.ServerVersion}}"], { encoding: "utf8" }).status === 0;
}

export function docker(args, options = {}) {
  const res = spawnSync("docker", args, { encoding: "utf8", timeout: 1_800_000, ...options });
  if (res.status !== 0) throw new Error(`docker ${args.join(" ")} failed: ${res.stderr}`);
  return res.stdout;
}

/** Polls `docker compose ps` until the service has exited; returns its exit code. */
export async function waitForExit(project, file, service, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const out = docker(["compose", "-p", project, "-f", file, "ps", "-a", "--format", "json", service]).trim();
    const rows = out.startsWith("[") ? JSON.parse(out) : out.split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const row = rows.find((r) => r.Service === service);
    if (row?.State === "exited") return row.ExitCode;
    if (Date.now() > deadline) throw new Error(`${service} did not finish within ${timeoutMs / 1000}s`);
    await new Promise((r) => setTimeout(r, 5000));
  }
}

function formatFinding(f) {
  let loc = f.app;
  if (f.file) loc += `/${f.file}`;
  if (f.field) loc += ` ${f.field}`;
  return `${f.severity}: ${loc} [${f.code}] ${f.message}`;
}

/** CLI: lint app directories or a catalog; exit 1 on any error finding. */
export function main(argv) {
  const opts = { json: false, requireSbom: false, registry: undefined, appDirs: [], catalog: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") opts.json = true;
    else if (a === "--require-sbom") opts.requireSbom = true;
    else if (a === "--registry") opts.registry = argv[++i];
    else if (a === "--catalog") opts.catalog = argv[++i];
    else if (a === "--app-dir") opts.appDirs.push(argv[++i]);
    else if (!a.startsWith("-")) opts.appDirs.push(a);
    else {
      process.stderr.write(`catalog-lint: unknown flag ${a}\n`);
      return 2;
    }
  }
  if (!opts.catalog && opts.appDirs.length === 0) {
    process.stderr.write("usage: catalog-lint [--json] [--require-sbom] [--registry R] (--catalog DIR | --app-dir DIR...)\n");
    return 2;
  }
  const composer = findComposer();
  if (composer.skip) {
    process.stderr.write(`catalog-lint: ${composer.skip}\n`);
    return 2;
  }
  const findings = [
    ...(opts.catalog ? composerLint(composer, { catalog: opts.catalog }, opts) : []),
    ...(opts.appDirs.length ? composerLint(composer, opts.appDirs, opts) : []),
  ];
  if (opts.json) process.stdout.write(`${JSON.stringify(findings, null, 2)}\n`);
  else for (const f of findings) process.stdout.write(`${formatFinding(f)}\n`);
  return errorsOf(findings).length > 0 ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
