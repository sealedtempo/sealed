// App-local catalog checks: manifest schema, fragment rules (docs/INTERFACES.md section 14),
// egress policy and waivers. The same file lives in each app owned by the apps-biz workstream;
// it should move into the catalog CI tooling once that exists.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse } from "yaml";

export const ALLOWED_SERVICE_KEYS = new Set([
  "image", "command", "entrypoint", "environment", "healthcheck", "depends_on", "volumes", "tmpfs",
  "user", "working_dir", "read_only", "stop_grace_period", "shm_size", "ulimits", "mem_limit", "cpus",
  "labels", "x-sealed-secrets",
]);
const IMAGE_REF = /^\{\{image:([a-z][a-z0-9-]*)\}\}$/;
const HOST_PORT = /^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}:\d{1,5}$/;

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

export function validateManifestSchema(manifest, schemaPath) {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(JSON.parse(readFileSync(schemaPath, "utf8")));
  if (validate(manifest)) return [];
  return validate.errors.map((e) => `manifest${e.instancePath || ""} ${e.message}`);
}

function walkStrings(value, path, visit) {
  if (typeof value === "string") visit(value, path);
  else if (Array.isArray(value)) value.forEach((v, i) => walkStrings(v, `${path}[${i}]`, visit));
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) walkStrings(v, `${path}.${k}`, visit);
  }
}

// Every "$" must be doubled: a single "$" would be interpolated by compose from the host env.
export function unescapedDollars(value) {
  const found = [];
  walkStrings(value, "", (s, path) => {
    if (/\$/.test(s.replace(/\$\$/g, ""))) found.push(path);
  });
  return found;
}

function serviceVolumeErrors(name, volumes, declared) {
  const errors = [];
  for (const [i, entry] of (volumes ?? []).entries()) {
    if (typeof entry !== "string") {
      errors.push(`services.${name}.volumes[${i}] must use the short "volume:/path" form`);
      continue;
    }
    const [source, target, ...rest] = entry.split(":");
    if (!target || !target.startsWith("/")) errors.push(`services.${name}.volumes[${i}] needs an absolute target`);
    if (/^[./~]/.test(source)) errors.push(`services.${name}.volumes[${i}] is a bind mount`);
    else if (!declared.has(source)) errors.push(`services.${name}.volumes[${i}] uses undeclared volume ${source}`);
    if (rest.length > 1 || (rest.length === 1 && rest[0] !== "ro")) {
      errors.push(`services.${name}.volumes[${i}] has unsupported options`);
    }
  }
  return errors;
}

export function lintFragment(app) {
  const { manifest, fragment } = app;
  const errors = [];
  const appId = manifest.id;
  const prefix = `${appId}-`;
  for (const key of Object.keys(fragment ?? {})) {
    if (key !== "services" && key !== "volumes") errors.push(`fragment top-level key ${key} is not allowed`);
  }
  const services = fragment.services ?? {};
  const declaredVolumes = new Set(Object.keys(fragment.volumes ?? {}));
  const imageNames = new Set((manifest.images ?? []).map((i) => i.name));
  const secretNames = new Set((manifest.secrets ?? []).map((s) => s.name));
  const usedImages = new Set();
  const usedSecrets = new Set();
  const usedVolumes = new Set();

  for (const [volume, spec] of Object.entries(fragment.volumes ?? {})) {
    if (!volume.startsWith(prefix)) errors.push(`volumes.${volume} must start with ${prefix}`);
    if (spec !== null && !(typeof spec === "object" && Object.keys(spec).length === 0)) {
      errors.push(`volumes.${volume} must have no options`);
    }
  }

  for (const [name, svc] of Object.entries(services)) {
    if (!name.startsWith(prefix)) errors.push(`services.${name} must start with ${prefix}`);
    for (const key of Object.keys(svc)) {
      if (!ALLOWED_SERVICE_KEYS.has(key)) errors.push(`services.${name}.${key} is not allowed`);
    }
    const ref = IMAGE_REF.exec(svc.image ?? "");
    if (!ref) errors.push(`services.${name}.image must be {{image:<name>}}`);
    else if (!imageNames.has(ref[1])) errors.push(`services.${name}.image names unknown image ${ref[1]}`);
    else usedImages.add(ref[1]);

    // The composer prepends envexec to the entrypoint, so every service states its entrypoint.
    if (!Array.isArray(svc.entrypoint) || svc.entrypoint.length === 0) {
      errors.push(`services.${name}.entrypoint must be an explicit list`);
    }
    if (svc.command !== undefined && !Array.isArray(svc.command)) {
      errors.push(`services.${name}.command must be a list`);
    }
    const secrets = svc["x-sealed-secrets"] ?? [];
    if (!Array.isArray(secrets)) errors.push(`services.${name}.x-sealed-secrets must be a list`);
    for (const secret of secrets) {
      if (!secretNames.has(secret)) errors.push(`services.${name} uses secret ${secret} not listed in the manifest`);
      usedSecrets.add(secret);
    }
    const env = svc.environment ?? {};
    if (Array.isArray(env)) errors.push(`services.${name}.environment must be a map`);
    for (const [key, value] of Object.entries(Array.isArray(env) ? {} : env)) {
      if (typeof value !== "string") errors.push(`services.${name}.environment.${key} must be a string`);
      if (secretNames.has(key)) errors.push(`services.${name}.environment.${key} is a secret name`);
      const off = manifest.telemetry_off_env ?? {};
      if (key in off && off[key] !== value) {
        errors.push(`services.${name}.environment.${key} conflicts with telemetry_off_env`);
      }
    }
    const deps = svc.depends_on ?? {};
    if (Array.isArray(deps)) errors.push(`services.${name}.depends_on must be a map with conditions`);
    for (const dep of Object.keys(Array.isArray(deps) ? {} : deps)) {
      if (!(dep in services)) errors.push(`services.${name}.depends_on ${dep} is not a service of this app`);
    }
    errors.push(...serviceVolumeErrors(name, svc.volumes, declaredVolumes));
    for (const entry of svc.volumes ?? []) if (typeof entry === "string") usedVolumes.add(entry.split(":")[0]);
    walkStrings(svc, `services.${name}`, (s, path) => {
      if (/docker\.sock|dstack\.sock/.test(s)) errors.push(`${path} mentions a host socket`);
    });
  }
  for (const path of unescapedDollars(fragment)) errors.push(`${path} has a "$" that is not doubled`);

  for (const image of imageNames) if (!usedImages.has(image)) errors.push(`manifest image ${image} is not used`);
  for (const secret of secretNames) if (!usedSecrets.has(secret)) errors.push(`manifest secret ${secret} is not used`);
  for (const volume of declaredVolumes) if (!usedVolumes.has(volume)) errors.push(`volume ${volume} is not used`);

  const mustExist = [
    ["primary_service", manifest.primary_service],
    ["healthcheck.service", manifest.healthcheck?.service],
    ...(manifest.routes ?? []).map((r, i) => [`routes[${i}].service`, r.service]),
  ];
  if (manifest.bootstrap) mustExist.push(["bootstrap.service", manifest.bootstrap.service]);
  for (const [field, service] of mustExist) {
    if (!(service in services)) errors.push(`manifest ${field} names unknown service ${service}`);
  }
  if (manifest.healthcheck?.service !== manifest.primary_service) {
    errors.push("manifest healthcheck.service must be the primary service");
  }
  if (manifest.bootstrap?.done_file) {
    const [volume, ...rest] = manifest.bootstrap.done_file.split("/");
    if (!declaredVolumes.has(volume) || rest.length === 0) {
      errors.push("manifest bootstrap.done_file must be <volume>/<path> on a volume of this app");
    }
  }
  return errors;
}

export function lintEgress(egress) {
  const errors = [];
  const allowed = new Set(["version", "default_allow", "customer_additions_allowed", "notes"]);
  for (const key of Object.keys(egress ?? {})) if (!allowed.has(key)) errors.push(`egress.${key} is not allowed`);
  if (egress?.version !== 1) errors.push("egress.version must be 1");
  if (!Array.isArray(egress?.default_allow)) errors.push("egress.default_allow must be a list");
  for (const entry of egress?.default_allow ?? []) {
    if (!HOST_PORT.test(entry)) errors.push(`egress.default_allow entry ${entry} is not host:port`);
  }
  if (typeof egress?.customer_additions_allowed !== "boolean") {
    errors.push("egress.customer_additions_allowed must be a boolean");
  }
  if (typeof egress?.notes !== "string" || egress.notes.length === 0) errors.push("egress.notes must explain the entries");
  return errors;
}

export function lintWaivers(waivers, manifest, today = new Date()) {
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

// Replaces {{image:<name>}} with a registry reference so docker compose can parse the fragment.
export function substituteImages(fragmentText, manifest, registry = "ghcr.io/sealed-dev") {
  const digests = new Map(manifest.images.map((i) => [i.name, i.digest]));
  return fragmentText.replace(/\{\{image:([a-z][a-z0-9-]*)\}\}/g, (_, name) => {
    const digest = digests.get(name);
    const usable = digest && !/^sha256:0{64}$/.test(digest) ? digest : `sha256:${"1".repeat(64)}`;
    return `${registry}/${name}@${usable}`;
  });
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
