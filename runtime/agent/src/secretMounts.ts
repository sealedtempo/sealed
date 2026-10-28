// Which secret files each service of the measured compose can see (brief item 5, D-042). The agent
// writes /run/sealed/secrets/<owner>/<NAME> into one tmpfs volume per owner. Composer 1.1 mounts an
// owner's whole directory into every service of that owner that declares secrets; composer 1.2 mounts
// only the files a service lists in `x-sealed-secrets`, one read-only mount per file (a volume
// `subpath` or a bind of the file). This module reads those mounts back from the compose so the agent
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
  // Compose's short syntax: a source that is a path is a bind mount, anything else names a volume.
  const type = source !== undefined && /^[./~]/.test(source) ? "bind" : "volume";
  return { type, source, target, read_only: mode?.split(",").includes("ro") ?? false };
}

/** The dstack guest agent's socket: whoever can reach it can get quotes and so ask the key broker for every secret. */
export const DSTACK_SOCKETS = ["/run/dstack.sock"];

/** A host path as Docker resolves it, for comparisons: normalized, no trailing slash, `/var/run` as `/run` (a symlink on the host). */
export function hostPath(p: string): string {
  let n = posix.normalize(p);
  if (n.length > 1) n = n.replace(/\/+$/, "");
  if (n.startsWith("//")) n = n.replace(/^\/+/, "/");
  if (n === "/var/run" || n.startsWith("/var/run/")) n = `/run${n.slice("/var/run".length)}`;
  return n;
}

const SECRET_FILE_RE = /^\/run\/sealed\/secrets\/(_gate|[a-z][a-z0-9-]*)\/[A-Z][A-Z0-9_]*$/;

/**
 * The second line behind the composer's fragment rules (review ws-int-agent 8): what a service other than
 * sealed-agent binds from the host or takes from a secrets volume, whatever its target. Refused: a bind of the
 * secrets root, anything above it (`/`, `/run`, `/run/sealed`) or anything below it except one secret file at its
 * own path (the owner check then applies to the target), a bind of the dstack socket, and a `sealed-secrets-*`
 * volume mounted outside the secrets root.
 */
function checkSource(service: string, v: ComposeVolume): void {
  if (service === AGENT_SERVICE || typeof v.source !== "string") return;
  const type = v.type ?? "volume";
  const where = `compose: ${service} mounts ${v.source}${typeof v.target === "string" ? ` at ${v.target}` : ""}`;
  if (type === "bind") {
    const src = hostPath(v.source);
    if (!src.startsWith("/")) throw new Error(`${where}: a relative bind source cannot be checked`);
    if (`${SECRETS_ROOT}/`.startsWith(src === "/" ? "/" : `${src}/`)) throw new Error(`${where}, which holds every owner's secrets`);
    if (src.startsWith(`${SECRETS_ROOT}/`)) {
      const target = typeof v.target === "string" ? hostPath(v.target) : undefined;
      if (!SECRET_FILE_RE.test(src) || target !== src) throw new Error(`${where}: only one secret file at its own path may be bound from ${SECRETS_ROOT}`);
    }
    if (DSTACK_SOCKETS.includes(src)) throw new Error(`${where}: only sealed-agent may reach the dstack socket`);
    return;
  }
  if (type === "volume" && v.source.startsWith(SECRETS_VOLUME_PREFIX)) {
    const target = typeof v.target === "string" ? hostPath(v.target) : "";
    if (target !== SECRETS_ROOT && !target.startsWith(`${SECRETS_ROOT}/`)) throw new Error(`${where}: a secrets volume outside ${SECRETS_ROOT}`);
  }
}

/** Every mount at or below /run/sealed/secrets in the compose. Malformed targets and unsafe sources are errors. */
export function secretMountsFromAppCompose(appCompose: string): SecretMount[] {
  const out: SecretMount[] = [];
  for (const [service, svc] of Object.entries(composeServices(appCompose))) {
    for (const raw of svc.volumes ?? []) {
      const v = typeof raw === "string" ? shortSyntax(raw) : raw;
      checkSource(service, v);
      if (typeof v.target !== "string") continue;
      const target = hostPath(v.target);
      if (target === SECRETS_ROOT) {
        out.push({ service, owner: "*", readOnly: v.read_only === true });
        continue;
      }
      if (!target.startsWith(`${SECRETS_ROOT}/`)) continue;
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
 * Owners whose secrets the agent writes: composer 1.1, the owner directories the compose mounts into the agent;
 * composer 1.2, which binds the whole /run/sealed/secrets into the agent, the owners some other service mounts
 * (D-042: a secret no container reads, such as the gate's hash, stays in the agent's memory).
 */
export function agentSecretOwners(mounts: SecretMount[]): Set<string> {
  const mine = mounts.filter((m) => m.service === AGENT_SERVICE && m.name === undefined);
  if (mine.some((m) => m.owner === "*")) return new Set(mounts.filter((m) => m.service !== AGENT_SERVICE).map((m) => m.owner));
  return new Set(mine.map((m) => m.owner));
}
