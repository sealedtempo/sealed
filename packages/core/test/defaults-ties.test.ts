// Ties config/defaults.yaml (spec 2.4) to the components that implement each key, for keys that no
// component reads (app_login, coding_agent, local_model, code_license) and for fee_splitter_caps_usd,
// whose deployed copy nothing compared with the file (spec conformance G30, package C08). Each check
// returns the mismatches it finds. The real repo must give none, and each test also edits one input in
// memory to show that the check catches the drift.
import { existsSync, lstatSync, readFileSync, readdirSync, readlinkSync } from "node:fs";
import { dirname, join, posix, relative, resolve } from "node:path";
import { decodeAbiParameters } from "viem";
import { describe, expect, it } from "vitest";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { z } from "zod";
import { type Defaults, parseDefaults, settlementDefaults } from "../src/defaults.js";

const ROOT = resolve(import.meta.dirname, "../../..");
const DEFAULTS = "config/defaults.yaml";

/** Read access to the repo by repo-relative path, so a test can swap single files. */
interface Repo {
  read(path: string): string;
  exists(path: string): boolean;
  list(dir: string): string[];
  /** The repo-relative target of a symlink, or the path itself. */
  target(path: string): string;
  packageJsonFiles(): string[];
}

// Directories that hold installed, vendored or built code, not files this repo authors.
const SKIP_DIRS = new Set(["node_modules", "dist", "build", "out", "cache", "lib", "dependencies", "vendor"]);

const repo: Repo = {
  read: (p) => readFileSync(join(ROOT, p), "utf8"),
  exists: (p) => existsSync(join(ROOT, p)),
  list: (d) => readdirSync(join(ROOT, d)).sort(),
  target(p) {
    const abs = join(ROOT, p);
    if (!lstatSync(abs).isSymbolicLink()) return p;
    return relative(ROOT, resolve(dirname(abs), readlinkSync(abs))).split("\\").join("/");
  },
  packageJsonFiles() {
    const out: string[] = [];
    const walk = (dir: string): void => {
      for (const e of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
        if (e.name.startsWith(".") || SKIP_DIRS.has(e.name)) continue;
        const p = dir ? `${dir}/${e.name}` : e.name;
        if (e.isDirectory()) walk(p);
        else if (e.name === "package.json") out.push(p);
      }
    };
    walk("");
    return out.sort();
  },
};

type Edit = string | null | ((text: string) => string);

/** `base` with some files replaced (string or function of the old text) or removed (null). */
function edited(base: Repo, edits: Record<string, Edit>): Repo {
  const has = (p: string) => Object.hasOwn(edits, p);
  return {
    read(p) {
      if (!has(p)) return base.read(p);
      const e = edits[p];
      if (e === null || e === undefined) throw new Error(`ENOENT: ${p}`);
      return typeof e === "function" ? e(base.read(p)) : e;
    },
    exists: (p) => (has(p) ? edits[p] !== null : base.exists(p)),
    list: (d) => base.list(d),
    target: (p) => base.target(p),
    packageJsonFiles: () => base.packageJsonFiles(),
  };
}

/** Replaces exactly one occurrence, so an edit that no longer applies fails loudly. */
function once(from: string, to: string): (text: string) => string {
  return (text) => {
    const at = text.indexOf(from);
    if (at < 0 || text.indexOf(from, at + 1) >= 0) throw new Error(`edit target ${JSON.stringify(from)} not found exactly once`);
    return text.slice(0, at) + to + text.slice(at + from.length);
  };
}

/** Edits a YAML file through its parsed form. */
function yamlEdit(fn: (doc: Record<string, unknown>) => void): (text: string) => string {
  return (text) => {
    const doc = parseYaml(text) as Record<string, unknown>;
    fn(doc);
    return stringifyYaml(doc);
  };
}

// The keys this file ties. The loader schema (src/defaults.ts) may or may not list them; the file must.
const tiedKeys = z
  .object({
    app_login: z.string(),
    coding_agent: z.object({ primary: z.string().min(1), fallback: z.string().min(1) }),
    local_model: z.object({
      max_params_b: z.number().positive(),
      licenses: z.array(z.string()).min(1),
      runtime: z.string(),
    }),
    code_license: z.object({ public_repo: z.string(), private_repo: z.string() }),
    chain: z.object({ deployments_file: z.string().min(1) }).loose(),
  })
  .loose();

function loadDefaults(r: Repo): { core: Defaults; ties: z.infer<typeof tiedKeys> } {
  const text = r.read(DEFAULTS);
  return { core: parseDefaults(text, { testOverrides: false }), ties: tiedKeys.parse(parseYaml(text)) };
}

interface Manifest {
  id?: string;
  upstream?: { repo?: string };
  primary_service?: string;
  images?: { name?: string; source?: string }[];
  routes?: { name?: string; auth?: string; on_attest_host?: boolean }[];
}

const readYaml = <T>(r: Repo, p: string): T => parseYaml(r.read(p)) as T;

/** github.com/<owner>/<name> of an upstream repo URL, lower case. */
function githubRepo(url: string | undefined): { owner: string; name: string } | undefined {
  const m = /^https:\/\/github\.com\/([^/]+)\/([^/#?]+?)(?:\.git)?\/?$/.exec(url ?? "");
  return m ? { owner: (m[1] as string).toLowerCase(), name: (m[2] as string).toLowerCase() } : undefined;
}

/** The image a manifest's primary service runs: `{{image:<name>}}` in its compose fragment. */
function primaryImage(r: Repo, dir: string, m: Manifest): { name?: string; source?: string } | undefined {
  const fragment = readYaml<{ services?: Record<string, { image?: string }> }>(r, `${dir}/compose.fragment.yaml`);
  const ref = /^\{\{image:([a-z0-9-]+)\}\}$/.exec(fragment.services?.[m.primary_service ?? ""]?.image ?? "")?.[1];
  return m.images?.find((i) => i.name === ref);
}

// ---------------------------------------------------------------------------------------------------
// app_login

const GATED_AUTH = new Set(["gate", "bearer-passthrough"]);

function checkAppLogin(r: Repo): string[] {
  const p: string[] = [];
  const { ties } = loadDefaults(r);
  if (ties.app_login !== "password-gate") {
    p.push(`app_login is ${JSON.stringify(ties.app_login)}, but the platform only builds password-gate (D-044)`);
  }

  // Caddy asks sealed-agent's gate before every route that is not public.
  const tmpl = r.read("runtime/caddy/Caddyfile.tmpl");
  const blocks = [...tmpl.matchAll(/forward_auth\s+(\S+)\s*\{\s*uri\s+(\S+)/g)];
  if (blocks.length < 2) p.push(`Caddyfile.tmpl has ${blocks.length} forward_auth blocks, want the gated and the bearer-passthrough one`);
  for (const [, upstream, uri] of blocks) {
    if (upstream !== "{{$.GateUpstream}}") p.push(`Caddyfile.tmpl forward_auth goes to ${upstream}, not {{$.GateUpstream}}`);
    if (!uri?.startsWith("{{$.GatePath}}?route={{$r.Name}}")) p.push(`Caddyfile.tmpl forward_auth uri is ${uri}, not {{$.GatePath}}?route={{$r.Name}}`);
  }
  const ifPublic = tmpl.indexOf('{{- if eq $r.Auth "public"}}');
  const elseAt = ifPublic < 0 ? -1 : tmpl.indexOf("{{- else}}", ifPublic);
  const endAt = elseAt < 0 ? -1 : tmpl.indexOf("{{- end}}", elseAt);
  const gatedBranch = endAt < 0 ? "" : tmpl.slice(elseAt, endAt);
  if (!/forward_auth \{\{\$\.GateUpstream\}\} \{\s*uri \{\{\$\.GatePath\}\}\?route=\{\{\$r\.Name\}\}\s/.test(gatedBranch)) {
    p.push("Caddyfile.tmpl: a route that is not public does not pass forward_auth to the gate");
  }

  // The composer fills those values with sealed-agent and /v1/gate, and the agent serves that path.
  if (!/DefaultGatePath\s*=\s*"\/v1\/gate"/.test(r.read("runtime/caddy/caddy.go"))) p.push("caddy.go DefaultGatePath is not /v1/gate");
  const compose = r.read("runtime/composer/compose.go");
  if (!/svcAgent\s*=\s*"sealed-agent"/.test(compose)) p.push('composer svcAgent is not "sealed-agent"');
  if (!/GateUpstream:\s*svcAgent \+ ":" \+ strconv\.Itoa\(AgentPort\)/.test(compose)) p.push("composer GateUpstream is not sealed-agent:<AgentPort>");
  if (!/GatePath:\s*caddy\.DefaultGatePath/.test(compose)) p.push("composer GatePath is not caddy.DefaultGatePath");
  if (!r.read("runtime/agent/src/server.ts").includes('case "GET /v1/gate"')) p.push("sealed-agent serves no GET /v1/gate");

  // "password": the gate checks the bcrypt hash that the key broker releases as _gate/GATE_PASSWORD_BCRYPT.
  if (!/GateSecretName\s*=\s*"GATE_PASSWORD_BCRYPT"/.test(r.read("key-broker/secrets.go"))) p.push("key broker gate secret is not GATE_PASSWORD_BCRYPT");
  if (!/secretApp:\s*"_gate",\s*secret:\s*"GATE_PASSWORD_BCRYPT"/.test(r.read("runtime/agent/src/stack.ts"))) p.push("sealed-agent gate secret is not _gate/GATE_PASSWORD_BCRYPT");
  if (!/import \{[^}]*\bparseBcrypt\b[^}]*\} from "\.\/bcrypt\.js"/.test(r.read("runtime/agent/src/gate/gate.ts"))) p.push("sealed-agent gate does not check a bcrypt hash");

  // Every app route is behind the gate, except public routes on the attest host (spec 5.5.3).
  let routes = 0;
  for (const app of r.list("catalog/apps")) {
    const path = `catalog/apps/${app}/manifest.yaml`;
    if (!r.exists(path)) continue;
    for (const route of readYaml<Manifest>(r, path).routes ?? []) {
      routes++;
      const auth = route.auth ?? "";
      if (GATED_AUTH.has(auth)) continue;
      if (auth === "public" && route.on_attest_host === true) continue;
      p.push(`${app} route ${route.name ?? "?"} has auth ${JSON.stringify(auth)}, which skips the password gate`);
    }
  }
  if (routes === 0) p.push("no catalog app has a route");
  return p;
}

// ---------------------------------------------------------------------------------------------------
// coding_agent

const CODING_AGENT = "catalog/apps/coding-agent";

function checkCodingAgent(r: Repo): string[] {
  const p: string[] = [];
  const { primary, fallback } = loadDefaults(r).ties.coding_agent;
  if (primary === fallback) p.push(`coding_agent primary and fallback are both ${primary}`);

  // The primary is what the release ships: catalog/apps/coding-agent itself (D-023).
  const main = readYaml<Manifest>(r, `${CODING_AGENT}/manifest.yaml`);
  if (main.id !== "coding-agent") p.push(`${CODING_AGENT}/manifest.yaml id is ${main.id}`);
  const up = githubRepo(main.upstream?.repo);
  if (up?.owner !== primary) p.push(`coding-agent upstream ${main.upstream?.repo} is not from ${primary}`);
  const img = primaryImage(r, CODING_AGENT, main);
  const org = /^ghcr\.io\/([^/]+)\//.exec(img?.source ?? "")?.[1]?.toLowerCase();
  if (org !== primary) p.push(`coding-agent primary service image ${img?.source} is not ghcr.io/${primary}/...`);

  // The fallback is a complete variant of the same app in fallback-<name>, built FROM its upstream image.
  const dir = `${CODING_AGENT}/fallback-${fallback}`;
  if (!r.exists(`${dir}/manifest.yaml`)) {
    p.push(`coding_agent fallback ${fallback} has no ${dir}/manifest.yaml`);
    return p;
  }
  const fb = readYaml<Manifest>(r, `${dir}/manifest.yaml`);
  if (fb.id !== "coding-agent") p.push(`${dir}/manifest.yaml id is ${fb.id}, not coding-agent`);
  if (fb.primary_service !== main.primary_service) p.push(`${dir} primary service ${fb.primary_service} differs from ${main.primary_service}`);
  if (githubRepo(fb.upstream?.repo)?.name !== fallback) p.push(`${dir} upstream ${fb.upstream?.repo} is not ${fallback}`);
  const fbImg = primaryImage(r, dir, fb);
  const build = /^build:(.+)$/.exec(fbImg?.source ?? "")?.[1];
  const dockerfile = build ? `${dir}/${build}/Dockerfile` : "";
  if (!build || !r.exists(dockerfile)) {
    p.push(`${dir} primary service image ${fbImg?.source} is not built from a Dockerfile here`);
  } else {
    const from = /^FROM\s+(?:--platform=\S+\s+)?(\S+)/m.exec(r.read(dockerfile))?.[1] ?? "";
    const name = /\/([^/:@]+)(?::[^/@]+)?@sha256:[0-9a-f]{64}$/.exec(from)?.[1];
    if (name !== fallback) p.push(`${dockerfile} is FROM ${from}, not a digest-pinned ${fallback} image`);
  }
  return p;
}

// ---------------------------------------------------------------------------------------------------
// local_model

const LOCAL_MODEL = "runtime/images/local-model";

function checkLocalModel(r: Repo): string[] {
  const p: string[] = [];
  const lm = loadDefaults(r).ties.local_model;
  const df = r.read(`${LOCAL_MODEL}/Dockerfile`);
  const model = /^ARG MODEL=(\S+)$/m.exec(df)?.[1] ?? "";

  // Nominal size from the Ollama tag (qwen3:4b-...). D-024 records the real count, 4.02B, marketed as 4B.
  const size = /^[a-z0-9._-]+:(\d+(?:\.\d+)?)b(?:-|$)/i.exec(model)?.[1];
  if (size === undefined) p.push(`local model tag ${JSON.stringify(model)} names no size`);
  else if (Number(size) > lm.max_params_b) p.push(`local model ${model} is ${size}B, above max_params_b ${lm.max_params_b}`);

  // The license the build copies out of the model's own license blob, named by SPDX id.
  const copy = /cp "\/models\/blobs\/sha256-\$LICENSE_BLOB" \/models\/licenses\/[^\s;.]+\.([A-Za-z0-9.+-]+)\.txt/.exec(df);
  if (!copy) p.push("the local-model build does not copy the model license to /models/licenses/<name without dots>.<SPDX>.txt");
  else if (!lm.licenses.includes(copy[1] as string)) p.push(`local model license ${copy[1]} is not in ${lm.licenses.join(", ")}`);

  // ollama-cpu: a digest-pinned Ollama base with every GPU runtime removed, flattened.
  if (lm.runtime !== "ollama-cpu") p.push(`local_model runtime is ${lm.runtime}, but the image is Ollama on CPU (ollama-cpu)`);
  if (!/^ARG OLLAMA_BASE=ollama\/ollama:[0-9.]+@sha256:[0-9a-f]{64}$/m.test(df)) p.push("the local-model base is not a digest-pinned ollama/ollama");
  for (const gpu of ["cuda_v12", "cuda_v13", "mlx_cuda_v13", "vulkan"]) {
    if (!df.includes(`/usr/lib/ollama/${gpu}`)) p.push(`the local-model build keeps /usr/lib/ollama/${gpu}`);
  }
  if (!/test -z "\$\(find \/usr\/lib\/ollama[^"]*-iname '\*cuda\*'[^"]*-iname '\*vulkan\*'/.test(df)) p.push("the local-model build does not fail on a leftover CUDA or Vulkan library");
  if (!/^\s*OLLAMA_VULKAN=0\b/m.test(df)) p.push("the local-model image does not set OLLAMA_VULKAN=0");
  const froms = [...df.matchAll(/^FROM\s+(.+)$/gm)].map((m) => (m[1] as string).trim());
  if (froms.at(-1) !== "scratch") p.push(`the local-model final stage is FROM ${froms.at(-1)}, not a flattened FROM scratch`);

  // The gateway serves this image and this model.
  const gw = readYaml<Manifest>(r, "catalog/apps/llm-gateway/manifest.yaml");
  const local = gw.images?.find((i) => i.source === "build:images/local-model");
  if (!local) p.push("llm-gateway has no build:images/local-model image");
  if (r.target("catalog/apps/llm-gateway/images/local-model") !== LOCAL_MODEL) p.push(`llm-gateway images/local-model is not ${LOCAL_MODEL}`);
  const litellm = readYaml<{ model_list?: { model_name?: string; litellm_params?: { model?: string } }[] }>(
    r,
    "catalog/apps/llm-gateway/images/litellm/config.yaml",
  );
  const named = (litellm.model_list ?? []).filter((m) => m.model_name?.startsWith("local/") && !m.model_name.includes("*"));
  if (named.length === 0) p.push("llm-gateway has no named local/ route");
  for (const m of named) {
    if (m.litellm_params?.model !== `ollama_chat/${model}`) p.push(`llm-gateway ${m.model_name} serves ${m.litellm_params?.model}, not ollama_chat/${model}`);
  }
  return p;
}

// ---------------------------------------------------------------------------------------------------
// fee_splitter_caps_usd

const FEE_SPLITTER_CTOR = [
  { type: "address", name: "initialOwner" },
  { type: "address", name: "deploymentRegistry" },
  { type: "address", name: "appRegistry" },
  { type: "address", name: "feeToken" },
  { type: "address", name: "treasury" },
  { type: "uint256", name: "perPaymentCap" },
  { type: "uint256", name: "perDeploymentDailyCap" },
] as const;

interface DeploymentsFile {
  chainId?: number;
  config?: { feeToken?: string; perPaymentCap?: string; perDeploymentDailyCap?: string };
  contracts?: Record<string, { address?: string; constructorArgs?: `0x${string}` }>;
}

const lower = (s: string | undefined) => (s ?? "").toLowerCase();

function checkFeeSplitterCaps(r: Repo): string[] {
  const p: string[] = [];
  const { core, ties } = loadDefaults(r);
  // The conversion the agent uses (fee_token_decimals), so the file and the chain agree in FEE_TOKEN units.
  const { perPaymentCap, perDeploymentDailyCap } = settlementDefaults(core);
  const want = { perPaymentCap, perDeploymentDailyCap };
  const file = ties.chain.deployments_file;
  const dep = JSON.parse(r.read(file)) as DeploymentsFile;

  if (dep.chainId !== core.chain.chain_id) p.push(`${file} chainId ${dep.chainId} is not ${core.chain.chain_id}`);
  if (lower(dep.config?.feeToken) !== lower(core.chain.fee_token)) p.push(`${file} feeToken ${dep.config?.feeToken} is not chain.fee_token`);
  for (const k of ["perPaymentCap", "perDeploymentDailyCap"] as const) {
    const got = dep.config?.[k];
    if (got === undefined || BigInt(got) !== want[k]) p.push(`${file} config.${k} is ${got}, defaults give ${want[k]}`);
  }

  // The FeeSplitter's constructor arguments are what the chain holds.
  const splitter = dep.contracts?.FeeSplitter;
  if (!splitter?.constructorArgs) {
    p.push(`${file} has no FeeSplitter constructorArgs`);
  } else {
    const [, deploymentRegistry, appRegistry, feeToken, , ctorPerPayment, ctorDaily] = decodeAbiParameters(FEE_SPLITTER_CTOR, splitter.constructorArgs);
    if (lower(deploymentRegistry) !== lower(dep.contracts?.DeploymentRegistry?.address)) p.push("FeeSplitter constructorArgs do not decode against this file (deploymentRegistry)");
    if (lower(appRegistry) !== lower(dep.contracts?.AppRegistry?.address)) p.push("FeeSplitter constructorArgs do not decode against this file (appRegistry)");
    if (lower(feeToken) !== lower(core.chain.fee_token)) p.push(`FeeSplitter was deployed with fee token ${feeToken}, not chain.fee_token`);
    if (ctorPerPayment !== perPaymentCap) p.push(`FeeSplitter was deployed with perPaymentCap ${ctorPerPayment}, defaults give ${perPaymentCap}`);
    if (ctorDaily !== perDeploymentDailyCap) p.push(`FeeSplitter was deployed with perDeploymentDailyCap ${ctorDaily}, defaults give ${perDeploymentDailyCap}`);
  }

  // The deploy script's fallbacks (used when PER_PAYMENT_CAP and PER_DEPLOYMENT_DAILY_CAP are unset).
  const script = r.read("contracts/script/Deploy.s.sol");
  const literal = (name: string): bigint | undefined => {
    const m = new RegExp(`uint256 internal constant ${name} = ([0-9_]+);`).exec(script);
    return m ? BigInt((m[1] as string).replaceAll("_", "")) : undefined;
  };
  const scriptPerPayment = literal("DEFAULT_PER_PAYMENT_CAP");
  const scriptDaily = literal("DEFAULT_DAILY_CAP");
  if (scriptPerPayment !== perPaymentCap) p.push(`Deploy.s.sol DEFAULT_PER_PAYMENT_CAP is ${scriptPerPayment}, defaults give ${perPaymentCap}`);
  if (scriptDaily !== perDeploymentDailyCap) p.push(`Deploy.s.sol DEFAULT_DAILY_CAP is ${scriptDaily}, defaults give ${perDeploymentDailyCap}`);
  return p;
}

// ---------------------------------------------------------------------------------------------------
// code_license

/** SPDX id of a license text, for the texts this repo may carry. */
function spdxOf(text: string): string | undefined {
  if (/^\s*Apache License\s+Version 2\.0, January 2004\s/.test(text)) return "Apache-2.0";
  if (/^\s*MIT License\s/.test(text)) return "MIT";
  return undefined;
}

/** pnpm-workspace.yaml entries here are directories, where `*` stands for one path segment. */
function workspaceGlobMatches(glob: string, dir: string): boolean {
  const a = glob.split("/");
  const b = dir.split("/");
  return a.length === b.length && a.every((seg, i) => seg === "*" || seg === b[i]);
}

function checkCodeLicense(r: Repo): string[] {
  const p: string[] = [];
  const { public_repo } = loadDefaults(r).ties.code_license;
  const spdx = spdxOf(r.read("LICENSE"));
  if (spdx !== public_repo) p.push(`LICENSE is ${spdx ?? "an unknown license"}, code_license.public_repo is ${public_repo}`);

  // Every package this repo authors declares the same license (D-069).
  const files = r.packageJsonFiles();
  const workspace = readYaml<{ packages?: string[] }>(r, "pnpm-workspace.yaml").packages ?? [];
  for (const glob of workspace) {
    const covered = files.some((f) => workspaceGlobMatches(glob, posix.dirname(f)));
    if (!covered) p.push(`no package.json found for workspace entry ${glob}`);
  }
  if (!files.includes("package.json")) p.push("no root package.json found");
  for (const f of files) {
    const license = (JSON.parse(r.read(f)) as { license?: unknown }).license;
    if (license !== public_repo) p.push(`${f} license is ${JSON.stringify(license)}, not ${public_repo}`);
  }
  return p;
}

// ---------------------------------------------------------------------------------------------------

const withDefaults = (fn: (d: Record<string, unknown>) => void): Repo => edited(repo, { [DEFAULTS]: yamlEdit(fn) });
const sub = (d: Record<string, unknown>, k: string) => d[k] as Record<string, unknown>;

describe("config/defaults.yaml ties to the components (spec 2.4, G30)", () => {
  it("the loader still accepts the file and every tied key is present", () => {
    const { ties } = loadDefaults(repo);
    expect(ties.app_login).toBe("password-gate");
    expect(ties.coding_agent).toEqual({ primary: "openhands", fallback: "opencode" });
    expect(ties.local_model.runtime).toBe("ollama-cpu");
    expect(() => loadDefaults(withDefaults((d) => delete d.local_model))).toThrow();
  });

  it("app_login: password-gate is Caddy forward_auth to sealed-agent /v1/gate, checking the released bcrypt hash", () => {
    expect(checkAppLogin(repo)).toEqual([]);
    expect(checkAppLogin(withDefaults((d) => (d.app_login = "oauth")))).toEqual([
      'app_login is "oauth", but the platform only builds password-gate (D-044)',
    ]);
    expect(checkAppLogin(edited(repo, { "runtime/caddy/caddy.go": once('DefaultGatePath = "/v1/gate"', 'DefaultGatePath = "/v2/gate"') }))).toEqual([
      "caddy.go DefaultGatePath is not /v1/gate",
    ]);
    const ungated = edited(repo, {
      "runtime/caddy/Caddyfile.tmpl": once("uri {{$.GatePath}}?route={{$r.Name}}\n", "uri /healthz\n"),
    });
    expect(checkAppLogin(ungated)).toEqual([
      "Caddyfile.tmpl forward_auth uri is /healthz, not {{$.GatePath}}?route={{$r.Name}}",
      "Caddyfile.tmpl: a route that is not public does not pass forward_auth to the gate",
    ]);
    const publicCrm = edited(repo, {
      "catalog/apps/crm/manifest.yaml": yamlEdit((m) => {
        for (const route of m.routes as Record<string, unknown>[]) route.auth = "public";
      }),
    });
    expect(checkAppLogin(publicCrm)).toEqual(['crm route crm has auth "public", which skips the password gate']);
  });

  it("coding_agent: openhands is the shipped coding-agent image and opencode the packaged fallback", () => {
    expect(checkCodingAgent(repo)).toEqual([]);
    const swapped = checkCodingAgent(withDefaults((d) => (d.coding_agent = { primary: "opencode", fallback: "openhands" })));
    expect(swapped).toContain("coding-agent upstream https://github.com/OpenHands/software-agent-sdk is not from opencode");
    expect(swapped).toContain("coding_agent fallback openhands has no catalog/apps/coding-agent/fallback-openhands/manifest.yaml");
    expect(checkCodingAgent(withDefaults((d) => (sub(d, "coding_agent").fallback = "aider")))).toEqual([
      "coding_agent fallback aider has no catalog/apps/coding-agent/fallback-aider/manifest.yaml",
    ]);
    const otherBase = edited(repo, {
      [`${CODING_AGENT}/fallback-opencode/images/opencode/Dockerfile`]: once("ghcr.io/anomalyco/opencode:", "ghcr.io/anomalyco/crush:"),
    });
    expect(checkCodingAgent(otherBase)).toHaveLength(1);
    expect(checkCodingAgent(otherBase)[0]).toMatch(/Dockerfile is FROM ghcr\.io\/anomalyco\/crush:.*, not a digest-pinned opencode image$/);
  });

  it("local_model: the baked model fits max_params_b and licenses, on the CPU-only Ollama runtime", () => {
    expect(checkLocalModel(repo)).toEqual([]);
    expect(checkLocalModel(withDefaults((d) => (sub(d, "local_model").max_params_b = 3)))).toEqual([
      "local model qwen3:4b-instruct-2507-q4_K_M is 4B, above max_params_b 3",
    ]);
    expect(checkLocalModel(withDefaults((d) => (sub(d, "local_model").licenses = ["MIT"])))).toEqual([
      "local model license Apache-2.0 is not in MIT",
    ]);
    expect(checkLocalModel(withDefaults((d) => (sub(d, "local_model").runtime = "vllm-gpu")))).toEqual([
      "local_model runtime is vllm-gpu, but the image is Ollama on CPU (ollama-cpu)",
    ]);
    const bigger = checkLocalModel(edited(repo, { [`${LOCAL_MODEL}/Dockerfile`]: once("ARG MODEL=qwen3:4b-", "ARG MODEL=qwen3:8b-") }));
    expect(bigger).toEqual([
      "local model qwen3:8b-instruct-2507-q4_K_M is 8B, above max_params_b 4",
      "llm-gateway local/qwen3-4b serves ollama_chat/qwen3:4b-instruct-2507-q4_K_M, not ollama_chat/qwen3:8b-instruct-2507-q4_K_M",
    ]);
    const gpu = checkLocalModel(edited(repo, { [`${LOCAL_MODEL}/Dockerfile`]: once(" /usr/lib/ollama/vulkan", "") }));
    expect(gpu).toEqual(["the local-model build keeps /usr/lib/ollama/vulkan"]);
  });

  it("fee_splitter_caps_usd: the deployed FeeSplitter caps equal the file in FEE_TOKEN units", () => {
    expect(checkFeeSplitterCaps(repo)).toEqual([]);
    expect(checkFeeSplitterCaps(withDefaults((d) => (sub(d, "fee_splitter_caps_usd").per_payment = 6)))).toEqual([
      "contracts/deployments/tempo-mainnet.json config.perPaymentCap is 5000000, defaults give 6000000",
      "FeeSplitter was deployed with perPaymentCap 5000000, defaults give 6000000",
      "Deploy.s.sol DEFAULT_PER_PAYMENT_CAP is 5000000, defaults give 6000000",
    ]);
    // Decimals matter: the same USD cap is a different onchain number for an 18-decimal token.
    expect(checkFeeSplitterCaps(withDefaults((d) => (sub(d, "chain").fee_token_decimals = 18)))).toHaveLength(6);
    const script = edited(repo, { "contracts/script/Deploy.s.sol": once("DEFAULT_DAILY_CAP = 20_000_000;", "DEFAULT_DAILY_CAP = 25_000_000;") });
    expect(checkFeeSplitterCaps(script)).toEqual(["Deploy.s.sol DEFAULT_DAILY_CAP is 25000000, defaults give 20000000"]);
    const redeployed = edited(repo, {
      "contracts/deployments/tempo-mainnet.json": once("01312d00", "01c9c380"),
    });
    expect(checkFeeSplitterCaps(redeployed)).toEqual(["FeeSplitter was deployed with perDeploymentDailyCap 30000000, defaults give 20000000"]);
  });

  it("code_license: LICENSE and every package.json are code_license.public_repo", () => {
    expect(checkCodeLicense(repo)).toEqual([]);
    expect(repo.packageJsonFiles()).toContain("packages/core/package.json");
    expect(checkCodeLicense(withDefaults((d) => (sub(d, "code_license").public_repo = "MIT")))).toContain(
      "LICENSE is Apache-2.0, code_license.public_repo is MIT",
    );
    const relicensed = edited(repo, { "packages/core/package.json": once('"license": "Apache-2.0"', '"license": "UNLICENSED"') });
    expect(checkCodeLicense(relicensed)).toEqual(['packages/core/package.json license is "UNLICENSED", not Apache-2.0']);
  });
});
