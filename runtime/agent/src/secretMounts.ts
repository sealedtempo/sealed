// Which secret files each service of the measured compose can see (brief item 5, D-042). The agent
// writes /run/sealed/secrets/<owner>/<NAME>. Composer 1.2 binds the host's /run/sealed/secrets (on the
// CVM's /run tmpfs) into the agent only, and binds into each service exactly the files it lists in
// `x-sealed-secrets`, read-only, from the same host path. Composer 1.1 mounted one tmpfs volume per
// owner, whole, into every service of that owner. This module reads those mounts back from the compose so the agent
// can (a) refuse a compose that hands one owner's secrets to another owner's service and (b) make sure
// every individually mounted file exists before the ready flag, since Docker cannot start a container
// whose mount source is missing.
import { posix } from "node:path";
import { parseCJSON } from "@sealed/core";
import { CADDY_SERVICE, PAYER_SERVICE, type StackInfo } from "./stack.js";

export const AGENT_SERVICE = "sealed-agent";
export const SECRETS_ROOT = "/run/sealed/secrets";
export const SECRETS_VOLUME_PREFIX = "sealed-secrets-";
const OWNER_RE = /^(_gate|[a-z][a-z0-9-]*)$/;
const NAME_RE = /^[A-Z][A-Z0-9_]*$/;

export interface SecretMount {
  service: string;
  /** The owner directory, or "*" for a mount of /run/sealed/secrets itself (only the agent may have one). */
  owner: string;
  /** The single file mounted; undefined when the owner's whole directory is mounted. */
  name?: string;
  readOnly: boolean;
}

/** A secret a service declares through envexec flags (`--secret` / `--optional-secret`). */
export interface DeclaredSecret {
  service: string;
  app: string;
  name: string;
  optional: boolean;
}

interface ComposeVolume {
  type?: string;
  source?: string;
  target?: string;
  read_only?: boolean;
  volume?: { subpath?: string };
}

interface ComposeService {
  entrypoint?: unknown;
  volumes?: (string | ComposeVolume)[];
}

function composeServices(appCompose: string): Record<string, ComposeService> {
  const outer = JSON.parse(appCompose) as { docker_compose_file?: unknown };
  if (typeof outer.docker_compose_file !== "string") throw new Error("app-compose.json has no docker_compose_file");
  const compose = parseCJSON(outer.docker_compose_file) as { services?: Record<string, ComposeService> };
  return compose.services ?? {};
}

function shortSyntax(v: string): ComposeVolume {
  const [source, target, mode] = v.split(":");
  return { source, target, read_only: mode?.split(",").includes("ro") ?? false };
}

/** Every mount at or below /run/sealed/secrets in the compose. Malformed targets are errors. */
export function secretMountsFromAppCompose(appCompose: string): SecretMount[] {
  const out: SecretMount[] = [];
  for (const [service, svc] of Object.entries(composeServices(appCompose))) {
    for (const raw of svc.volumes ?? []) {
      const v = typeof raw === "string" ? shortSyntax(raw) : raw;
      if (typeof v.target !== "string") continue;
      const target = posix.normalize(v.target).replace(/\/$/, "");
      if (target !== SECRETS_ROOT && !target.startsWith(`${SECRETS_ROOT}/`)) continue;
      // A bind under the secrets root must bind the same host path, so a service can only ever see
      // the file its target names (review finding: targets alone were checked).
      if (v.type === "bind" && (typeof v.source !== "string" || posix.normalize(v.source).replace(/\/$/, "") !== target)) {
        throw new Error(`compose: ${service} binds ${String(v.source)} at ${v.target}; secret binds must use the same host path`);
      }
      if (target === SECRETS_ROOT) {
        out.push({ service, owner: "*", readOnly: v.read_only === true });
        continue;
      }
      const parts = target.slice(SECRETS_ROOT.length + 1).split("/");
      const [owner, name, ...rest] = parts;
      const where = `${service} mounts ${v.target}`;
      if (!owner || rest.length > 0 || !OWNER_RE.test(owner) || (name !== undefined && !NAME_RE.test(name))) {
        throw new Error(`compose: ${where}, which is not /run/sealed/secrets/<owner>[/<NAME>]`);
      }
      if ((v.type ?? "volume") === "volume" && v.source !== undefined && v.source !== `${SECRETS_VOLUME_PREFIX}${owner}`) {
        throw new Error(`compose: ${where} from volume ${v.source}, not ${SECRETS_VOLUME_PREFIX}${owner}`);
      }
      const subpath = v.volume?.subpath;
      if (subpath !== undefined && subpath !== name) throw new Error(`compose: ${where} with subpath ${subpath}`);
      out.push({ service, owner, ...(name !== undefined ? { name } : {}), readOnly: v.read_only === true });
    }
  }
  return out.sort((a, b) => `${a.service}/${a.owner}/${a.name ?? ""}`.localeCompare(`${b.service}/${b.owner}/${b.name ?? ""}`));
}

/** The secrets each service declares through the envexec flags the composer puts in its entrypoint. */
export function declaredSecretsFromAppCompose(appCompose: string): DeclaredSecret[] {
  const out: DeclaredSecret[] = [];
  for (const [service, svc] of Object.entries(composeServices(appCompose))) {
    const ep = Array.isArray(svc.entrypoint) ? (svc.entrypoint as unknown[]) : [];
    if (typeof ep[0] !== "string" || !ep[0].endsWith("/envexec")) continue;
    const end = ep.indexOf("--");
    const flags = (end < 0 ? ep : ep.slice(0, end)).map(String);
    const app = flags[flags.indexOf("--app") + 1];
    if (flags.indexOf("--app") < 0 || !app) continue;
    for (let i = 1; i < flags.length - 1; i++) {
      if (flags[i] === "--secret" || flags[i] === "--optional-secret") {
        out.push({ service, app, name: flags[i + 1] as string, optional: flags[i] === "--optional-secret" });
      }
    }
  }
  return out;
}

/**
 * Fails when any service but sealed-agent can see secrets it does not own: an app's services only
 * their app's, caddy only `_gate`, sealed-mpp-payer only its own key, every other sidecar nothing.
 * Only the agent may mount a secrets directory writable.
 */
export function checkSecretMounts(mounts: SecretMount[], stack: StackInfo): void {
  const ownerOf = new Map<string, string>();
  for (const app of stack.apps) for (const s of app.services) ownerOf.set(s.name, app.id);
  ownerOf.set(CADDY_SERVICE, "_gate");
  ownerOf.set(PAYER_SERVICE, PAYER_SERVICE);
  for (const m of mounts) {
    if (m.service === AGENT_SERVICE) continue;
    if (m.owner === "*") throw new Error(`compose: service ${m.service} mounts every owner's secrets (${SECRETS_ROOT})`);
    const allowed = ownerOf.get(m.service);
    if (allowed !== m.owner) {
      throw new Error(`compose: service ${m.service} mounts the secrets of ${m.owner}${allowed ? `, but it belongs to ${allowed}` : ""}`);
    }
    if (!m.readOnly) throw new Error(`compose: service ${m.service} mounts the secrets of ${m.owner} writable`);
  }
}

/** owner -> names that some service mounts as a single file (each must exist before that service starts). */
export function filesMountedIndividually(mounts: SecretMount[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const m of mounts) {
    if (m.service === AGENT_SERVICE || m.name === undefined) continue;
    const names = out.get(m.owner) ?? new Set<string>();
    names.add(m.name);
    out.set(m.owner, names);
  }
  return out;
}

/** What a service can read: the files of its mounted owner directories plus its single-file mounts. */
export function visibleSecrets(mounts: SecretMount[], service: string, written: Record<string, string[]>): string[] {
  const seen = new Set<string>();
  for (const m of mounts) {
    if (m.service !== service) continue;
    if (m.name !== undefined) seen.add(`${m.owner}/${m.name}`);
    else if (m.owner === "*") for (const [o, names] of Object.entries(written)) for (const n of names) seen.add(`${o}/${n}`);
    else for (const n of written[m.owner] ?? []) seen.add(`${m.owner}/${n}`);
  }
  return [...seen].sort();
}

/**
 * Owners whose secrets directory the compose mounts into the agent, or undefined when the agent
 * mounts /run/sealed/secrets as a whole (then every released owner is written).
 */
export function agentSecretOwners(mounts: SecretMount[]): Set<string> | undefined {
  const mine = mounts.filter((m) => m.service === AGENT_SERVICE && m.name === undefined);
  if (mine.some((m) => m.owner === "*")) return undefined;
  return new Set(mine.map((m) => m.owner));
}

/**
 * sealed-stack/v1 `secretFiles` (composer 1.2) as owner -> names, or undefined for an older stack.
 * Every single-file secret mount of the compose must be listed, and every listed file must be bound
 * into some service, so the agent writes exactly what the containers bind.
 */
export function secretFilesFromStack(stack: StackInfo, mounts: SecretMount[]): Map<string, Set<string>> | undefined {
  if (stack.secretFiles === undefined) return undefined;
  const root = (stack.secretsRoot ?? SECRETS_ROOT).replace(/\/$/, "");
  if (root !== SECRETS_ROOT) throw new Error(`stack: secretsRoot ${root} is not ${SECRETS_ROOT}`);
  const out = new Map<string, Set<string>>();
  for (const f of stack.secretFiles) {
    const parts = f.startsWith(`${root}/`) ? f.slice(root.length + 1).split("/") : [];
    const [owner, name] = parts;
    if (parts.length !== 2 || !owner || !name || !OWNER_RE.test(owner) || !NAME_RE.test(name)) {
      throw new Error(`stack: secret file ${f} is not ${root}/<owner>/<NAME>`);
    }
    const names = out.get(owner) ?? new Set<string>();
    names.add(name);
    out.set(owner, names);
  }
  const bound = filesMountedIndividually(mounts);
  const key = (m: Map<string, Set<string>>) => [...m].flatMap(([o, ns]) => [...ns].map((n) => `${o}/${n}`)).sort();
  const listed = key(out);
  const mounted = key(bound);
  if (listed.join(",") !== mounted.join(",")) {
    throw new Error(`stack: secretFiles (${listed.join(", ")}) differ from the compose's secret binds (${mounted.join(", ")})`);
  }
  return out;
}
