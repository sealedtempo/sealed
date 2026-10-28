// App-local test helpers for internal-tools: loading the app files, the waivers format check (the
// composer does not read waivers.yaml; this belongs in catalog/tools/ with the release CI's waiver
// rules once that exists), memory sums, Docker helpers, and the compose document of the opt-in
// contract tests. The catalog rules themselves are checked only by the real composer
// (tests/lib/composer.mjs).

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { parse } from "yaml";

export function loadApp(appDir) {
  const read = (name) => readFileSync(join(appDir, name), "utf8");
  const fragmentText = read("compose.fragment.yaml");
  return {
    dir: appDir,
    manifest: parse(read("manifest.yaml")),
    fragmentText,
    fragment: parse(fragmentText),
    egress: parse(read("egress.yaml")),
    waivers: parse(read("waivers.yaml")),
  };
}

// The x-sealed-owner of each named volume of the fragment (integration brief item 11).
export function volumeOwners(fragment) {
  return new Map(Object.entries(fragment.volumes ?? {}).map(([name, spec]) => [name, spec?.["x-sealed-owner"]]));
}

export function checkWaivers(waivers, manifest, today = new Date()) {
  const errors = [];
  if (waivers?.version !== 1) errors.push("waivers.version must be 1");
  if (!Array.isArray(waivers?.waivers)) return [...errors, "waivers.waivers must be a list"];
  const images = new Set(manifest.images.map((i) => i.name));
  for (const [i, w] of waivers.waivers.entries()) {
    for (const field of ["id", "image", "package", "expires", "reason"]) {
      if (!w?.[field]) errors.push(`waivers[${i}].${field} is required`);
    }
    if (w?.image && !images.has(w.image)) errors.push(`waivers[${i}].image ${w.image} is not a manifest image`);
    const expires = new Date(`${w?.expires}T23:59:59Z`);
    if (Number.isNaN(expires.getTime())) errors.push(`waivers[${i}].expires is not a date`);
    else if (expires < today) errors.push(`waivers[${i}] expired on ${w.expires}`);
  }
  return errors;
}

export function dockerComposeAvailable() {
  const res = spawnSync("docker", ["compose", "version"], { encoding: "utf8" });
  return res.status === 0;
}

export function composeConfig(file, project) {
  const res = spawnSync("docker", ["compose", "-p", project, "-f", file, "config", "--format", "json"], {
    encoding: "utf8",
  });
  if (res.status !== 0) return { ok: false, stderr: res.stderr };
  return { ok: true, config: JSON.parse(res.stdout) };
}

export function readIfExists(path) {
  return existsSync(path) ? readFileSync(path, "utf8") : undefined;
}

// Parses a compose memory value ("2g", "512m", "1024k") into MiB.
export function memMiB(value) {
  const m = /^(\d+(?:\.\d+)?)([kmg])b?$/i.exec(String(value).trim());
  if (!m) throw new Error(`cannot read mem_limit ${value}`);
  const n = Number(m[1]);
  return { k: n / 1024, m: n, g: n * 1024 }[m[2].toLowerCase()];
}

// A compose document for booting an app with Docker outside the VM (contract tests), with what
// the composer and sealed-agent provide in the VM: upstream images by digest (or locally built
// tags), each secret as an env var and as a read-only bind of exactly the files a service lists
// (/run/sealed/secrets/<appId>/<NAME>, integration brief item 5), the manifest's
// telemetry_off_env and SEALED_PUBLIC_URL_<ROUTE> on every service (item 8), an init service that
// gives each named volume its x-sealed-owner (item 11), and the route port published on 127.0.0.1.
export function contractCompose(app, { secrets, secretsDir, publicUrl, hostPort, builtImages = {} }) {
  const refs = new Map(
    app.manifest.images.map((i) => [i.name, builtImages[i.name] ?? `${i.source.replace(/:[^:/]+$/, "")}@${i.digest}`]),
  );
  const text = app.fragmentText.replace(/\{\{image:([a-z][a-z0-9-]*)\}\}/g, (_, name) => refs.get(name));
  const doc = parse(text);
  const appId = app.manifest.id;
  const route = app.manifest.routes[0];
  const urlVar = `SEALED_PUBLIC_URL_${route.name.toUpperCase().replaceAll("-", "_")}`;
  for (const [name, svc] of Object.entries(doc.services)) {
    const env = { ...(svc.environment ?? {}), ...app.manifest.telemetry_off_env, [urlVar]: publicUrl };
    const listed = svc["x-sealed-secrets"] ?? [];
    for (const secret of listed) env[secret] = secrets[secret];
    svc.environment = env;
    delete svc["x-sealed-secrets"];
    const binds = listed.map((secret) => ({
      type: "bind",
      source: join(secretsDir, secret),
      target: `/run/sealed/secrets/${appId}/${secret}`,
      read_only: true,
    }));
    svc.volumes = [...(svc.volumes ?? []), ...binds];
    if (name === route.service) svc.ports = [`127.0.0.1:${hostPort}:${route.internal_port}`];
  }
  const owners = [...volumeOwners(doc)].filter(([, owner]) => owner);
  for (const name of Object.keys(doc.volumes ?? {})) doc.volumes[name] = {};
  if (owners.length > 0) {
    const init = `${appId}-contract-init`;
    const mounts = owners.map(([v]) => `${v}:/sealed-init/${v}`);
    const script = owners.map(([v, owner]) => `chown ${owner} /sealed-init/${v}`).join(" && ");
    const anyService = Object.values(doc.services)[0];
    doc.services[init] = { image: anyService.image, user: "0:0", entrypoint: ["/bin/sh", "-c", script], volumes: mounts };
    for (const svc of Object.values(doc.services)) {
      if (svc === doc.services[init]) continue;
      svc.depends_on = { ...(svc.depends_on ?? {}), [init]: { condition: "service_completed_successfully" } };
    }
  }
  return doc;
}

export function dockerDaemonAvailable() {
  return spawnSync("docker", ["info", "--format", "{{.ServerVersion}}"], { encoding: "utf8" }).status === 0;
}

export function docker(args, options = {}) {
  const res = spawnSync("docker", args, { encoding: "utf8", timeout: 1_800_000, ...options });
  if (res.status !== 0) throw new Error(`docker ${args.join(" ")} failed: ${res.stderr}`);
  return res.stdout;
}

// Polls `docker compose ps` until the service has exited; returns its exit code.
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
