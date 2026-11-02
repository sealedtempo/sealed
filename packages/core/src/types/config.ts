// sealed-config/v1 (INTERFACES section 5). Public, measured, never holds secrets.
//
// The TypeScript twin of the Go composer's ParseConfig (runtime/composer/config.go): it accepts and refuses exactly
// what ParseConfig followed by the config-only rules of Compose (validateComposable) accept and refuse, and its output
// is the composer's normalized form, so cjsonSha256(output) is the composer's configHash. One deliberate difference:
// the composer refuses any composerVersion but its own, which this schema cannot know (the platform serves several
// composer versions), so it only requires one. TestConfigParity (Go) and test/configParity.test.ts run both sides over
// runtime/composer/testdata/config-parity.json; change both sides together.
//
// Go decodes the document into a typed struct first: a JSON null, or a missing field, leaves the field's zero value
// ("", 0, false, an empty list or map), and the rules below then judge that zero value as the composer does. So a null
// relayOwner or gracePeriodMinutes is accepted (as absent and 0), and a null chainId is refused (0 is not positive).
import { z } from "zod";
import { CJSONError, parseCJSON } from "../cjson.js";
import { utf8 } from "../hex.js";
import { devEndpoint, endpointHostPort, goParseURL, parseHostPort, parseHostPortIn, parseIPv4, parseVpcRange, type Prefix4 } from "./hostport.js";

export const CONFIG_SCHEMA = "sealed-config/v1";
/** The path of endpoints.relayAttest: the relay deployment's sealed-agent attestation endpoint. */
export const RELAY_ATTEST_PATH = "/attest";

/** Config size bounds (config.go). */
export const MAX_CONFIG_BYTES = 128 * 1024;
export const MAX_CONFIG_APPS = 16;
export const MAX_EGRESS_ADDITIONS_PER_APP = 64;
export const MAX_EGRESS_ADDITIONS_TOTAL = 256;
export const MAX_ALLOWED_VPC_RANGES = 32;

/** The Caddy routes a stack can expose (config.go routeNames: manifest route names plus attest). */
export const ROUTE_NAMES: ReadonlySet<string> = new Set(["gateway", "scraper", "crm", "code", "tools", "relay", "attest"]);
/** App ids no manifest may use (manifest.go reservedAppIDs, plus every id starting with sealed-). */
export const RESERVED_APP_IDS: ReadonlySet<string> = new Set(["sealed", "caddy", "gate", "localhost"]);
const GATEWAY_APP = "llm-gateway";

const APP_ID = /^[a-z][a-z0-9-]{1,30}[a-z0-9]$/;
const HASH32 = /^0x[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const DECIMAL = /^(0|[1-9][0-9]{0,77})$/;
const ZERO_HASH = `0x${"0".repeat(64)}`;

/** config.runtimeImages: the runtime sidecar image set (runtime-images.json), part of configHash (D-097). */
export const RUNTIME_IMAGES_SCHEMA = "sealed-runtime-images/v1";
/** The sidecar images every runtime image set must name (composer runtimeimages.go). */
export const RUNTIME_IMAGE_NAMES = ["caddy", "sealed-agent", "sealed-egress", "sealed-init", "sealed-mpp-payer", "sealed-verifierd"] as const;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const DIGEST_REF = /^[a-z0-9][a-z0-9.-]*(:[0-9]+)?(\/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}$/;
const ZERO_DIGEST = `sha256:${"0".repeat(64)}`;

// --- decoding: the shapes encoding/json accepts into composer.Config, with the composer's exact key names ----------

const gStr = z.string().nullish();
const gInt = z.number().int().min(-Number.MAX_SAFE_INTEGER).max(Number.MAX_SAFE_INTEGER).nullish();
const gBool = z.boolean().nullish();
const gStrList = z.array(gStr).nullish();

/**
 * map[string]V: an object (or null) whose every value decodes as `value`. Not z.record, which builds its output by
 * assignment, so a "__proto__" key would set the prototype and vanish instead of being judged (and refused) as a key.
 */
function gMap<V>(value: z.ZodType<V>) {
  return z.unknown().transform((v, ctx): Record<string, V> | undefined => {
    if (v === null || v === undefined) return undefined;
    if (typeof v !== "object" || Array.isArray(v)) {
      ctx.addIssue({ code: "custom", message: "expected an object" });
      return z.NEVER;
    }
    const out: [string, V][] = [];
    for (const k of Object.keys(v)) {
      const r = value.safeParse((v as Record<string, unknown>)[k]);
      if (!r.success) {
        for (const issue of r.error.issues) ctx.addIssue({ code: "custom", message: issue.message, path: [k, ...issue.path] });
        return z.NEVER;
      }
      out.push([k, r.data]);
    }
    // Object.fromEntries defines own properties, "__proto__" included.
    return Object.fromEntries(out);
  }).optional();
}

const decodeSchema = z.strictObject({
  schema: gStr,
  chainId: gInt,
  customer: gStr,
  salt: gStr,
  imageId: gStr,
  composerVersion: gStr,
  apps: z.array(z.strictObject({ id: gStr, releaseId: gStr }).nullish()).nullish(),
  hostnames: z.strictObject({ scheme: gStr, ip: gStr, domains: gMap(gStr) }).nullish(),
  egressAdditions: gMap(gStrList),
  allowedVpcRanges: gStrList,
  endpoints: z.strictObject({ keyBroker: gStr, platformApi: gStr, tempoRpc: gStr, relay: gStr, relayAttest: gStr }).nullish(),
  contracts: z.strictObject({ platformRegistry: gStr, appRegistry: gStr, deploymentRegistry: gStr, feeSplitter: gStr }).nullish(),
  feeToken: gStr,
  settlement: z.strictObject({ mode: gStr, intervalMinutes: gInt, gracePeriodMinutes: gInt, spendLimitPerDay: gStr }).nullish(),
  relayOwner: gStr,
  debug: gBool,
  runtimeImages: z
    .strictObject({
      schema: gStr,
      registry: gStr,
      images: gMap(z.strictObject({ digest: gStr, source: gStr, license_spdx: gStr, unbuilt: gBool, notes: gStr }).nullish()),
    })
    .nullish(),
});

type Decoded = z.output<typeof decodeSchema>;

/** composer.Config with Go's zero values filled in. */
interface GoConfig {
  schema: string;
  chainId: number;
  customer: string;
  salt: string;
  imageId: string;
  composerVersion: string;
  apps: { id: string; releaseId: string }[];
  hostnames: { scheme: string; ip: string; domains: Record<string, string> };
  egressAdditions: Record<string, string[]>;
  allowedVpcRanges: string[];
  endpoints: { keyBroker: string; platformApi: string; tempoRpc: string; relay: string; relayAttest: string };
  contracts: { platformRegistry: string; appRegistry: string; deploymentRegistry: string; feeSplitter: string };
  feeToken: string;
  settlement: { mode: string; intervalMinutes: number; gracePeriodMinutes: number; spendLimitPerDay: string };
  relayOwner: string;
  debug: boolean;
  runtimeImages: {
    schema: string;
    registry: string;
    images: Record<string, { digest: string; source: string; license_spdx: string; unbuilt: boolean; notes: string }>;
  };
}

const s = (v: string | null | undefined) => v ?? "";
const strList = (v: readonly (string | null | undefined)[] | null | undefined) => (v ?? []).map(s);
const strMap = <V, W>(v: Record<string, V> | null | undefined, f: (x: V) => W): Record<string, W> =>
  Object.fromEntries(Object.keys(v ?? {}).map((k) => [k, f((v as Record<string, V>)[k] as V)]));

function toGo(d: Decoded): GoConfig {
  const h = d.hostnames;
  const e = d.endpoints;
  const c = d.contracts;
  const st = d.settlement;
  return {
    schema: s(d.schema),
    chainId: d.chainId ?? 0,
    customer: s(d.customer),
    salt: s(d.salt),
    imageId: s(d.imageId),
    composerVersion: s(d.composerVersion),
    apps: (d.apps ?? []).map((a) => ({ id: s(a?.id), releaseId: s(a?.releaseId) })),
    hostnames: { scheme: s(h?.scheme), ip: s(h?.ip), domains: strMap(h?.domains, s) },
    egressAdditions: strMap(d.egressAdditions, strList),
    allowedVpcRanges: strList(d.allowedVpcRanges),
    endpoints: { keyBroker: s(e?.keyBroker), platformApi: s(e?.platformApi), tempoRpc: s(e?.tempoRpc), relay: s(e?.relay), relayAttest: s(e?.relayAttest) },
    contracts: { platformRegistry: s(c?.platformRegistry), appRegistry: s(c?.appRegistry), deploymentRegistry: s(c?.deploymentRegistry), feeSplitter: s(c?.feeSplitter) },
    feeToken: s(d.feeToken),
    settlement: { mode: s(st?.mode), intervalMinutes: st?.intervalMinutes ?? 0, gracePeriodMinutes: st?.gracePeriodMinutes ?? 0, spendLimitPerDay: s(st?.spendLimitPerDay) },
    relayOwner: s(d.relayOwner),
    debug: d.debug ?? false,
    runtimeImages: {
      schema: s(d.runtimeImages?.schema),
      registry: s(d.runtimeImages?.registry),
      images: strMap(d.runtimeImages?.images, (img) => ({
        digest: s(img?.digest),
        source: s(img?.source),
        license_spdx: s(img?.license_spdx),
        unbuilt: img?.unbuilt ?? false,
        notes: s(img?.notes),
      })),
    },
  };
}

// --- the composer's rules: Validate, then validateComposable --------------------------------------------------------

interface Problem {
  path: (string | number)[];
  message: string;
}

const sortedKeys = (o: Record<string, unknown>) => Object.keys(o).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

/** config.go Validate, in its order; the first problem, as the composer reports one. */
function validate(c: GoConfig, devSim: boolean): Problem | undefined {
  const p = (path: (string | number)[], message: string): Problem => ({ path, message });
  if (c.schema !== CONFIG_SCHEMA) return p(["schema"], `must be ${JSON.stringify(CONFIG_SCHEMA)}`);
  if (c.chainId <= 0) return p(["chainId"], "must be positive");
  if (c.composerVersion === "") return p(["composerVersion"], "must name the composer version");
  const ri = validateRuntimeImages(c);
  if (ri) return ri;
  const addresses: [(string | number)[], string][] = [
    [["customer"], c.customer],
    [["feeToken"], c.feeToken],
    [["contracts", "platformRegistry"], c.contracts.platformRegistry],
    [["contracts", "appRegistry"], c.contracts.appRegistry],
    [["contracts", "deploymentRegistry"], c.contracts.deploymentRegistry],
    [["contracts", "feeSplitter"], c.contracts.feeSplitter],
  ];
  for (const [path, v] of addresses) if (!ADDRESS.test(v)) return p(path, `${JSON.stringify(v)} is not a 0x-prefixed lowercase 20-byte address`);
  if (c.relayOwner !== "" && !ADDRESS.test(c.relayOwner)) return p(["relayOwner"], `${JSON.stringify(c.relayOwner)} is not a 0x-prefixed lowercase 20-byte address`);
  if (!HASH32.test(c.salt)) return p(["salt"], `${JSON.stringify(c.salt)} is not 0x-prefixed lowercase hex of 32 bytes`);
  if (!HASH32.test(c.imageId) || c.imageId === ZERO_HASH) return p(["imageId"], "must be a non-zero 32-byte hex id");
  if (c.apps.length === 0 || c.apps.length > MAX_CONFIG_APPS) return p(["apps"], `between 1 and ${MAX_CONFIG_APPS} apps are required`);
  for (const [i, a] of c.apps.entries()) {
    const prev = c.apps[i - 1];
    if (prev && prev.id >= a.id) return p(["apps"], `must be sorted by id without duplicates (${JSON.stringify(a.id)} after ${JSON.stringify(prev.id)})`);
    if (!HASH32.test(a.releaseId)) return p(["apps", i, "releaseId"], `${JSON.stringify(a.releaseId)} is not 0x-prefixed lowercase hex of 32 bytes`);
  }
  const h = validateHostnames(c);
  if (h) return h;
  if (c.allowedVpcRanges.length > MAX_ALLOWED_VPC_RANGES) return p(["allowedVpcRanges"], `at most ${MAX_ALLOWED_VPC_RANGES} ranges`);
  const vpc: Prefix4[] = [];
  for (const [i, r] of c.allowedVpcRanges.entries()) {
    const pr = parseVpcRange(r);
    if (typeof pr === "string") return p(["allowedVpcRanges", i], pr);
    vpc.push(pr);
  }
  const appIds = new Set(c.apps.map((a) => a.id));
  let total = 0;
  for (const app of sortedKeys(c.egressAdditions)) {
    if (!appIds.has(app)) return p(["egressAdditions"], `${JSON.stringify(app)} is not an app in this stack`);
    const list = c.egressAdditions[app] as string[];
    if (list.length > MAX_EGRESS_ADDITIONS_PER_APP) return p(["egressAdditions", app], `${list.length} entries, at most ${MAX_EGRESS_ADDITIONS_PER_APP} per app`);
    total += list.length;
    const seen = new Set<string>();
    for (const [i, e] of list.entries()) {
      const hp = parseHostPortIn(e, vpc);
      if (typeof hp === "string") return p(["egressAdditions", app, i], hp);
      if (seen.has(e)) return p(["egressAdditions", app, i], `duplicate ${JSON.stringify(e)}`);
      seen.add(e);
    }
  }
  if (total > MAX_EGRESS_ADDITIONS_TOTAL) return p(["egressAdditions"], `${total} entries, at most ${MAX_EGRESS_ADDITIONS_TOTAL} in total`);
  const endpoint = devSim ? devEndpoint : endpointHostPort;
  const ep = c.endpoints;
  const endpoints: [string, string, boolean][] = [
    ["keyBroker", ep.keyBroker, true],
    ["platformApi", ep.platformApi, true],
    ["tempoRpc", ep.tempoRpc, true],
    ["relay", ep.relay, false],
    ["relayAttest", ep.relayAttest, false],
  ];
  for (const [name, v, required] of endpoints) {
    if (v === "" && !required) continue;
    const r = endpoint(v);
    if (typeof r !== "string") return p(["endpoints", name], r.error);
  }
  if (ep.relayAttest !== "") {
    // The relay deployment's agent serves /attest; any other path (the relay app's /v1/... on the same host) would
    // not be the agent's attestation (review C-11).
    const u = goParseURL(ep.relayAttest);
    if (!u || u.path !== RELAY_ATTEST_PATH || u.rawQuery !== "" || u.forceQuery || u.fragment !== "") {
      return p(["endpoints", "relayAttest"], `${JSON.stringify(ep.relayAttest)} must be https://<relay attest host>${RELAY_ATTEST_PATH} without a query`);
    }
  }
  const st = c.settlement;
  if (st.mode !== "access-key" && st.mode !== "enclave-account") return p(["settlement", "mode"], "must be access-key or enclave-account");
  if (st.intervalMinutes <= 0 || st.gracePeriodMinutes < 0) return p(["settlement"], "intervalMinutes must be positive and gracePeriodMinutes non-negative");
  if (!DECIMAL.test(st.spendLimitPerDay)) return p(["settlement", "spendLimitPerDay"], "must be a decimal string of base units");
  return validateComposable(c);
}

/** composer RuntimeImagesFromConfig + finalizeRuntimeImages: config.runtimeImages names every sidecar by a valid digest (D-097). */
function validateRuntimeImages(c: GoConfig): Problem | undefined {
  const ri = c.runtimeImages;
  // Optional across composer versions (like composerVersion, the schema cannot know which version this is):
  // pre-D-097 stacks carry no runtime image set. The Go composer, which knows it is 1.7+, requires it; here it is
  // validated only when present. An absent set normalizes away (normalize), so an old config's configHash is unchanged.
  if (ri.schema === "" && ri.registry === "" && Object.keys(ri.images).length === 0) return undefined;
  if (ri.schema !== RUNTIME_IMAGES_SCHEMA) return { path: ["runtimeImages"], message: `unknown schema ${JSON.stringify(ri.schema)}` };
  for (const name of RUNTIME_IMAGE_NAMES) {
    const img = ri.images[name];
    if (!img) return { path: ["runtimeImages"], message: `missing ${name}` };
    if (!DIGEST.test(img.digest)) return { path: ["runtimeImages"], message: `${name}: invalid digest` };
    if ((img.digest === ZERO_DIGEST) !== img.unbuilt) return { path: ["runtimeImages"], message: `${name}: unbuilt must be true exactly when the digest is all zeros` };
  }
  for (const name of Object.keys(ri.images)) {
    const ref = `${ri.registry}/${name}@${(ri.images[name] as { digest: string }).digest}`;
    if (!DIGEST_REF.test(ref)) return { path: ["runtimeImages"], message: `${name}: invalid reference ${JSON.stringify(ref)}` };
  }
  return undefined;
}

/** config.go validateHostnames. */
function validateHostnames(c: GoConfig): Problem | undefined {
  const h = c.hostnames;
  const ipv4 = (ip: string) => parseIPv4(ip) !== undefined;
  if (h.scheme === "sslip") {
    if (!ipv4(h.ip)) return { path: ["hostnames", "ip"], message: `${JSON.stringify(h.ip)} must be an IPv4 address` };
    if (Object.keys(h.domains).length > 0) return { path: ["hostnames", "domains"], message: "only allowed with scheme custom" };
    return undefined;
  }
  if (h.scheme !== "custom") return { path: ["hostnames", "scheme"], message: "must be sslip or custom" };
  if (h.ip !== "" && !ipv4(h.ip)) return { path: ["hostnames", "ip"], message: `${JSON.stringify(h.ip)} must be an IPv4 address` };
  const seen = new Map<string, string>();
  for (const route of sortedKeys(h.domains)) {
    const d = h.domains[route] as string;
    if (!ROUTE_NAMES.has(route)) return { path: ["hostnames", "domains"], message: `unknown route ${JSON.stringify(route)}` };
    const hp = parseHostPort(`${d}:443`);
    if (typeof hp === "string" || hp.ip || hp.wildcard) return { path: ["hostnames", "domains", route], message: `${JSON.stringify(d)} must be a lowercase DNS name` };
    const other = seen.get(d);
    if (other !== undefined) return { path: ["hostnames", "domains"], message: `${JSON.stringify(d)} is used by both ${other} and ${route}` };
    seen.set(d, route);
  }
  return undefined;
}

/**
 * config.go validateComposable: the rules Compose applies that depend on the config alone. App ids are manifest ids,
 * the custom scheme names the attest route's domain, and with llm-gateway the relay endpoints and relayOwner are set,
 * the relay exactly the origin of relayAttest (D-045).
 */
function validateComposable(c: GoConfig): Problem | undefined {
  for (const [i, a] of c.apps.entries()) {
    if (!APP_ID.test(a.id) || RESERVED_APP_IDS.has(a.id) || a.id.startsWith("sealed-")) return { path: ["apps", i, "id"], message: `${JSON.stringify(a.id)} is not an app id` };
  }
  if (c.hostnames.scheme === "custom" && !Object.hasOwn(c.hostnames.domains, "attest")) {
    return { path: ["hostnames", "domains"], message: `route "attest" has no domain` };
  }
  if (!c.apps.some((a) => a.id === GATEWAY_APP)) return undefined;
  const ep = c.endpoints;
  if (ep.relay === "" || ep.relayAttest === "" || c.relayOwner === "") {
    const missing = ep.relay === "" ? ["endpoints", "relay"] : ep.relayAttest === "" ? ["endpoints", "relayAttest"] : ["relayOwner"];
    return { path: missing, message: `endpoints.relay, endpoints.relayAttest and relayOwner are required when ${GATEWAY_APP} is in the stack` };
  }
  // compose.go checkRelayOrigin, on url.Parse's fields.
  const r = goParseURL(ep.relay);
  const a = goParseURL(ep.relayAttest);
  if (!r || !a) return { path: ["endpoints", "relay"], message: "not a valid URL" };
  if (r.path !== "" || r.rawQuery !== "" || r.fragment !== "" || r.opaque !== "") {
    return { path: ["endpoints", "relay"], message: `${JSON.stringify(ep.relay)} must be an origin (scheme and host, no path or trailing slash)` };
  }
  if (r.scheme !== a.scheme || r.host !== a.host) {
    return { path: ["endpoints", "relay"], message: `${JSON.stringify(ep.relay)} must equal the origin of endpoints.relayAttest (${a.scheme}://${a.host}) (D-045)` };
  }
  return undefined;
}

// --- the normalized form: what composer.Config encodes to (omitempty fields left out when empty) ---------------------

export type SealedConfigHostnames = { scheme: "sslip"; ip: string } | { scheme: "custom"; ip?: string; domains: Record<string, string> };

export type SealedConfig = {
  schema: typeof CONFIG_SCHEMA;
  chainId: number;
  customer: string;
  salt: string;
  imageId: string;
  composerVersion: string;
  apps: { id: string; releaseId: string }[];
  hostnames: SealedConfigHostnames;
  egressAdditions: Record<string, string[]>;
  allowedVpcRanges: string[];
  endpoints: { keyBroker: string; platformApi: string; tempoRpc: string; relay?: string; relayAttest?: string };
  contracts: { platformRegistry: string; appRegistry: string; deploymentRegistry: string; feeSplitter: string };
  feeToken: string;
  settlement: { mode: "access-key" | "enclave-account"; intervalMinutes: number; gracePeriodMinutes: number; spendLimitPerDay: string };
  relayOwner?: string;
  /** Container logs on (`local` driver) when true; part of configHash, so it is always present (composer 1.2). */
  debug: boolean;
  /** The runtime sidecar image set the composer pins; part of configHash (composer 1.7+, D-097). Absent on older stacks. */
  runtimeImages?: {
    schema: string;
    registry: string;
    images: Record<string, { digest: string; source: string; license_spdx: string; unbuilt?: boolean; notes?: string }>;
  };
};

function normalize(c: GoConfig): SealedConfig {
  const hostnames: SealedConfigHostnames =
    c.hostnames.scheme === "sslip"
      ? { scheme: "sslip", ip: c.hostnames.ip }
      : { scheme: "custom", ...(c.hostnames.ip !== "" ? { ip: c.hostnames.ip } : {}), domains: c.hostnames.domains };
  const { relay, relayAttest, ...required } = c.endpoints;
  return {
    schema: CONFIG_SCHEMA,
    chainId: c.chainId,
    customer: c.customer,
    salt: c.salt,
    imageId: c.imageId,
    composerVersion: c.composerVersion,
    apps: c.apps,
    hostnames,
    egressAdditions: c.egressAdditions,
    allowedVpcRanges: c.allowedVpcRanges,
    endpoints: { ...required, ...(relay !== "" ? { relay } : {}), ...(relayAttest !== "" ? { relayAttest } : {}) },
    contracts: c.contracts,
    feeToken: c.feeToken,
    settlement: c.settlement as SealedConfig["settlement"],
    ...(c.relayOwner !== "" ? { relayOwner: c.relayOwner } : {}),
    debug: c.debug,
    // Present only on composer 1.7+ stacks (D-097); omitted otherwise so an older config's configHash is unchanged.
    ...(Object.keys(c.runtimeImages.images).length > 0 || c.runtimeImages.schema !== ""
      ? {
          runtimeImages: {
            schema: c.runtimeImages.schema,
            registry: c.runtimeImages.registry,
            images: Object.fromEntries(
              Object.keys(c.runtimeImages.images).map((name) => {
                const img = c.runtimeImages.images[name] as { digest: string; source: string; license_spdx: string; unbuilt: boolean; notes: string };
                return [
                  name,
                  { digest: img.digest, source: img.source, license_spdx: img.license_spdx, ...(img.unbuilt ? { unbuilt: true } : {}), ...(img.notes !== "" ? { notes: img.notes } : {}) },
                ];
              }),
            ),
          },
        }
      : {}),
  };
}

function configSchema(devSim: boolean) {
  return decodeSchema.transform((d, ctx): SealedConfig => {
    const g = toGo(d);
    const problem = validate(g, devSim);
    if (problem) {
      ctx.addIssue({ code: "custom", path: problem.path, message: problem.message });
      return z.NEVER;
    }
    return normalize(g);
  });
}

/**
 * A sealed-config/v1 document as the composer accepts it; the output is the composer's normalized form (absent or
 * null egressAdditions, allowedVpcRanges and debug filled in, empty optional fields left out).
 */
export const sealedConfigSchema = configSchema(false);

/**
 * sealedConfigSchema for SEALED_DEV_SIM=1 only (local tests and the devnet, never a production stack): the five
 * endpoints may also be plain http and name any host, loopback included. Every other rule is the composer's.
 */
export const devSimSealedConfigSchema = configSchema(true);

/** "apps[0].releaseId", the composer's way of naming a field. */
export function configFieldPath(path: readonly PropertyKey[]): string {
  return path.map((k, i) => (typeof k === "number" ? `[${k}]` : i === 0 ? String(k) : `.${String(k)}`)).join("");
}

/** A config the composer would refuse; `field` names the first offending field as the composer does, when known. */
export class SealedConfigError extends Error {
  constructor(
    message: string,
    readonly field?: string,
  ) {
    super(message);
    this.name = "SealedConfigError";
  }
}

/**
 * composer.ParseConfig: at most 128 KiB, canonical-JSON input (no floats, duplicate keys or non-ASCII keys), an object,
 * then sealedConfigSchema. Throws SealedConfigError.
 */
export function parseSealedConfig(text: string, o: { devSim?: boolean } = {}): SealedConfig {
  const bytes = utf8(text).length;
  if (bytes > MAX_CONFIG_BYTES) throw new SealedConfigError(`config: ${bytes} bytes, at most ${MAX_CONFIG_BYTES}`);
  let json: unknown;
  try {
    json = parseCJSON(text);
  } catch (err) {
    if (err instanceof CJSONError) throw new SealedConfigError(`config: ${err.message}`);
    throw err;
  }
  if (json === null || typeof json !== "object" || Array.isArray(json)) throw new SealedConfigError("config: top level must be an object");
  const parsed = (o.devSim ? devSimSealedConfigSchema : sealedConfigSchema).safeParse(json);
  if (!parsed.success) throw configError(parsed.error.issues);
  return parsed.data;
}

/** The first issue as the composer would name it (an unknown key by its own path, as checkExactKeys does). */
export function configError(issues: readonly z.core.$ZodIssue[]): SealedConfigError {
  const issue = issues[0];
  if (!issue) return new SealedConfigError("config: invalid");
  const path = issue.code === "unrecognized_keys" ? [...issue.path, [...issue.keys].sort()[0] as string] : issue.path;
  const field = configFieldPath(path);
  const what = issue.code === "unrecognized_keys" ? "unknown field" : issue.message;
  return new SealedConfigError(`config: ${field || "document"}: ${what}`, field || undefined);
}

/** The hostname Caddy serves a route on (sslip: <route>.<ip-with-dashes>.sslip.io). */
export function routeHostname(config: Pick<SealedConfig, "hostnames">, route: string): string | undefined {
  const h = config.hostnames;
  if (h.scheme === "sslip") return `${route}.${h.ip.replaceAll(".", "-")}.sslip.io`;
  return h.domains[route];
}
