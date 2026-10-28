// Brief item 5 (D-042): what each service of the measured compose can see under /run/sealed/secrets,
// on the composer's golden stack (composer 1.2: the agent binds the host's secrets directory, every
// other service binds exactly the files it declares).
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { canonicalize } from "@sealed/core";
import { describe, expect, it } from "vitest";
import {
  agentSecretOwners,
  checkSecretMounts,
  declaredSecretsFromAppCompose,
  filesMountedIndividually,
  secretFilesFromStack,
  secretMountsFromAppCompose,
  visibleSecrets,
} from "../src/secretMounts.js";
import { measuredConfigs, parseStackInfo } from "../src/stack.js";

const golden = await readFile(join(import.meta.dirname, "fixtures/composer-golden/app-compose.json"), "utf8");
const goldenStack = parseStackInfo(measuredConfigs(golden)["sealed-stack"] as string);
const golden12 = await readFile(join(import.meta.dirname, "fixtures/composer-golden-1.2/app-compose.json"), "utf8");
const golden12Stack = parseStackInfo(measuredConfigs(golden12)["sealed-stack"] as string);

/** The composer 1.2 golden app-compose with `edit` applied to its services. */
function edit12(edit: (services: Record<string, { volumes: Record<string, unknown>[] }>) => void): string {
  const outer = JSON.parse(golden12);
  const compose = JSON.parse(outer.docker_compose_file);
  edit(compose.services);
  outer.docker_compose_file = canonicalize(compose);
  return canonicalize(outer);
}

/** The golden app-compose with an edit to its services. */
function variant(edit: (services: Record<string, { volumes: Record<string, unknown>[] }>) => void): string {
  const outer = JSON.parse(golden);
  const compose = JSON.parse(outer.docker_compose_file);
  edit(compose.services);
  outer.docker_compose_file = canonicalize(compose);
  return canonicalize(outer);
}

const bind = (path: string, extra: Record<string, unknown> = {}) => ({ type: "bind", source: path, target: path, read_only: true, bind: { create_host_path: false }, ...extra });

describe("secret mounts in the measured compose", () => {
  it("reads the golden stack's mounts: the agent binds the root, each service exactly its own files", () => {
    const mounts = secretMountsFromAppCompose(golden);
    expect(mounts.filter((m) => m.service === "sealed-agent")).toEqual([{ service: "sealed-agent", owner: "*", readOnly: false }]);
    expect(mounts.filter((m) => m.service !== "sealed-agent")).toEqual([
      { service: "llm-gateway-proxy", owner: "llm-gateway", name: "MASTER_KEY", readOnly: true },
      { service: "notes-db", owner: "notes", name: "DB_PASSWORD", readOnly: true },
      { service: "notes-web", owner: "notes", name: "APP_SECRET", readOnly: true },
      { service: "notes-web", owner: "notes", name: "DB_PASSWORD", readOnly: true },
      { service: "notes-web", owner: "notes", name: "SMTP_PASSWORD", readOnly: true },
      { service: "sealed-mpp-payer", owner: "sealed-mpp-payer", name: "ENCLAVE_KEY", readOnly: true },
      { service: "sealed-mpp-payer", owner: "sealed-mpp-payer", name: "SPEND_LIMIT_PER_DAY", readOnly: true },
    ]);
    expect(() => checkSecretMounts(mounts, goldenStack)).not.toThrow();
    expect([...(filesMountedIndividually(mounts).get("notes") ?? [])].sort()).toEqual(["APP_SECRET", "DB_PASSWORD", "SMTP_PASSWORD"]);
    expect([...agentSecretOwners(mounts)].sort()).toEqual(["llm-gateway", "notes", "sealed-mpp-payer"]);
    // Caddy holds no secret any more: the gate hash stays in the agent.
    expect(mounts.some((m) => m.service === "caddy")).toBe(false);
  });

  it("matches the stack's secretFiles with the compose's binds", () => {
    const mounts = secretMountsFromAppCompose(golden);
    const files = secretFilesFromStack(goldenStack, mounts);
    expect(Object.fromEntries([...(files ?? [])].map(([o, n]) => [o, [...n].sort()]))).toEqual({
      "llm-gateway": ["MASTER_KEY"],
      notes: ["APP_SECRET", "DB_PASSWORD", "SMTP_PASSWORD"],
      "sealed-mpp-payer": ["ENCLAVE_KEY", "SPEND_LIMIT_PER_DAY"],
    });
    const fewer = variant((svcs) => {
      const db = svcs["notes-db"] as { volumes: Record<string, unknown>[] };
      db.volumes = db.volumes.filter((v) => !String(v.target).startsWith("/run/sealed/secrets/"));
      const web = svcs["notes-web"] as { volumes: Record<string, unknown>[] };
      web.volumes = web.volumes.filter((v) => v.target !== "/run/sealed/secrets/notes/DB_PASSWORD");
    });
    expect(() => secretFilesFromStack(goldenStack, secretMountsFromAppCompose(fewer))).toThrow("differ from the compose's secret binds");
    expect(secretFilesFromStack({ ...goldenStack, secretFiles: undefined }, mounts)).toBeUndefined();
    expect(() => secretFilesFromStack({ ...goldenStack, secretFiles: ["/run/sealed/secrets/notes/a/B"] }, mounts)).toThrow("is not /run/sealed/secrets/<owner>/<NAME>");
  });

  it("lets only the agent mount the whole secrets root", () => {
    const mounts = secretMountsFromAppCompose(golden);
    // The agent binds the root and writes the owners other services mount; Caddy mounts nothing, so `_gate` is not among them.
    expect([...agentSecretOwners(mounts)].sort()).toEqual(["llm-gateway", "notes", "sealed-mpp-payer"]);
    expect(() => checkSecretMounts(mounts, goldenStack)).not.toThrow();
    // A bind of the root by an app service is refused while reading the compose (review ws-int-agent 8) ...
    const appRootBind = variant((svcs) => {
      svcs["notes-web"]?.volumes.push(bind("/run/sealed/secrets"));
    });
    expect(() => secretMountsFromAppCompose(appRootBind)).toThrow("holds every owner's secrets");
    // ... and a volume at the root by the owner check.
    const appRoot = variant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets", target: "/run/sealed/secrets/", read_only: true });
    });
    expect(() => checkSecretMounts(secretMountsFromAppCompose(appRoot), goldenStack)).toThrow("notes-web mounts every owner's secrets");
  });

  it("reads the declared secrets from the envexec flags", () => {
    const declared = declaredSecretsFromAppCompose(golden);
    expect(declared).toEqual(
      expect.arrayContaining([
        { service: "notes-web", app: "notes", name: "SMTP_PASSWORD", optional: true },
        { service: "notes-web", app: "notes", name: "APP_SECRET", optional: false },
        { service: "notes-db", app: "notes", name: "DB_PASSWORD", optional: false },
      ]),
    );
    expect(declared.some((d) => d.service === "caddy")).toBe(false);
  });

  it("each service sees exactly the secrets it declares", () => {
    const mounts = secretMountsFromAppCompose(golden);
    const written = { notes: ["APP_SECRET", "DB_PASSWORD", "SMTP_PASSWORD"], "llm-gateway": ["MASTER_KEY"] };
    const declared = declaredSecretsFromAppCompose(golden);
    for (const service of new Set(declared.map((d) => d.service))) {
      const own = declared.filter((x) => x.service === service).map((x) => `${x.app}/${x.name}`).sort();
      expect(visibleSecrets(mounts, service, written)).toEqual(own);
    }
  });

  it("refuses another owner's secrets, writable mounts, foreign bind sources and malformed targets", () => {
    const cross = variant((svcs) => {
      svcs["notes-web"]?.volumes.push(bind("/run/sealed/secrets/llm-gateway/MASTER_KEY"));
    });
    expect(() => checkSecretMounts(secretMountsFromAppCompose(cross), goldenStack)).toThrow("notes-web mounts the secrets of llm-gateway, but it belongs to notes");
    const sidecar = variant((svcs) => {
      (svcs["sealed-egress"] as { volumes: unknown[] }).volumes.push(bind("/run/sealed/secrets/notes/APP_SECRET"));
    });
    expect(() => checkSecretMounts(secretMountsFromAppCompose(sidecar), goldenStack)).toThrow("sealed-egress mounts the secrets of notes");
    const writable = variant((svcs) => {
      svcs["notes-db"]?.volumes.push(bind("/run/sealed/secrets/notes/APP_SECRET", { read_only: false }));
    });
    expect(() => checkSecretMounts(secretMountsFromAppCompose(writable), goldenStack)).toThrow("writable");
    const foreignSource = variant((svcs) => {
      svcs["notes-web"]?.volumes.push({ ...bind("/run/sealed/secrets/notes/X"), source: "/run/sealed/secrets/llm-gateway/MASTER_KEY" });
    });
    // Another owner's file is refused by the bind source check (review ws-int-agent 8), any other host path at a
    // secrets target by the same-path rule, also for the agent.
    expect(() => secretMountsFromAppCompose(foreignSource)).toThrow("only one secret file at its own path");
    const elsewhere = variant((svcs) => {
      svcs["notes-web"]?.volumes.push({ ...bind("/run/sealed/secrets/notes/X"), source: "/srv/notes-x" });
    });
    expect(() => secretMountsFromAppCompose(elsewhere)).toThrow("secret binds must use the same host path");
    const agentElsewhere = variant((svcs) => {
      svcs["sealed-agent"]?.volumes.push({ ...bind("/run/sealed/secrets/notes/X"), source: "/srv/notes-x" });
    });
    expect(() => secretMountsFromAppCompose(agentElsewhere)).toThrow("secret binds must use the same host path");
    const wrongVolume = variant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets-llm-gateway", target: "/run/sealed/secrets/notes/X", read_only: true });
    });
    expect(() => secretMountsFromAppCompose(wrongVolume)).toThrow("not sealed-secrets-notes");
    const wrongSubpath = variant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets-notes", target: "/run/sealed/secrets/notes/X", read_only: true, volume: { subpath: "Y" } });
    });
    expect(() => secretMountsFromAppCompose(wrongSubpath)).toThrow("subpath Y");
    // A malformed target: as a bind the source check refuses it first, as a volume the target check.
    const deep = variant((svcs) => {
      svcs["notes-web"]?.volumes.push(bind("/run/sealed/secrets/notes/A/B"));
    });
    expect(() => secretMountsFromAppCompose(deep)).toThrow("only one secret file at its own path");
    const deepVolume = variant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets-notes", target: "/run/sealed/secrets/notes/A/B", read_only: true });
    });
    expect(() => secretMountsFromAppCompose(deepVolume)).toThrow("not /run/sealed/secrets/<owner>[/<NAME>]");
  });

  it("composer 1.2: the agent binds the host's secrets root, every other service binds single files of its own owner", () => {
    const mounts = secretMountsFromAppCompose(golden12);
    expect(() => checkSecretMounts(mounts, golden12Stack)).not.toThrow();
    // Caddy holds no secret in 1.2: the gate's hash is not written anywhere.
    expect([...agentSecretOwners(mounts)].sort()).toEqual(["llm-gateway", "notes", "sealed-mpp-payer"]);
    expect(mounts.filter((m) => m.service === "notes-db")).toEqual([{ service: "notes-db", owner: "notes", name: "DB_PASSWORD", readOnly: true }]);
    expect([...(filesMountedIndividually(mounts).get("sealed-mpp-payer") ?? [])].sort()).toEqual(["ENCLAVE_KEY", "SPEND_LIMIT_PER_DAY"]);
  });

  // Review ws-int-agent 8: mounts were classified by target only, so a bind could carry another owner's file
  // (or the whole root) to a harmless-looking target.
  it("refuses bind sources that reach other owners' secrets or the dstack socket, whatever the target", () => {
    const bind = (service: string, source: string, target: string) =>
      edit12((svcs) => {
        svcs[service]?.volumes.push({ type: "bind", source, target, read_only: true, bind: { create_host_path: false } });
      });
    // The review's reproduction: another owner's file under the service's own owner's path, and the whole root elsewhere.
    expect(() => secretMountsFromAppCompose(bind("notes-web", "/run/sealed/secrets/llm-gateway/MASTER_KEY", "/run/sealed/secrets/notes/MASTER_KEY"))).toThrow(
      "only one secret file at its own path",
    );
    expect(() => secretMountsFromAppCompose(bind("notes-web", "/run/sealed/secrets", "/srv/everything"))).toThrow("holds every owner's secrets");
    for (const source of ["/", "/run", "/run/sealed", "/run/sealed/", "/var/run/sealed/secrets", "//run/sealed", "/run/./sealed/../sealed"]) {
      expect(() => secretMountsFromAppCompose(bind("notes-db", source, "/srv/x")), source).toThrow("holds every owner's secrets");
    }
    expect(() => secretMountsFromAppCompose(bind("notes-db", "/run/sealed/secrets/notes", "/srv/notes"))).toThrow("only one secret file");
    expect(() => secretMountsFromAppCompose(bind("notes-db", "/run/sealed/secrets/notes/DB_PASSWORD", "/etc/pw"))).toThrow("only one secret file");
    expect(() => secretMountsFromAppCompose(bind("caddy", "/var/run/dstack.sock", "/var/run/dstack.sock"))).toThrow("only sealed-agent may reach the dstack socket");
    expect(() => secretMountsFromAppCompose(bind("notes-db", "./run", "/srv/x"))).toThrow("relative bind source");
    // Short syntax is read the same way.
    const short = edit12((svcs) => {
      (svcs["notes-web"] as { volumes: unknown[] }).volumes.push("/run/sealed:/srv/sealed:ro");
    });
    expect(() => secretMountsFromAppCompose(short)).toThrow("holds every owner's secrets");
    // A secrets volume mounted outside the secrets root.
    const vol = edit12((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets-llm-gateway", target: "/srv/keys", read_only: true });
    });
    expect(() => secretMountsFromAppCompose(vol)).toThrow("a secrets volume outside /run/sealed/secrets");
    // A file of the service's own owner at its own path is what the composer emits; another owner's is refused by owner.
    const own = bind("notes-db", "/run/sealed/secrets/notes/APP_SECRET", "/run/sealed/secrets/notes/APP_SECRET");
    expect(() => checkSecretMounts(secretMountsFromAppCompose(own), golden12Stack)).not.toThrow();
    const other = bind("notes-db", "/run/sealed/secrets/llm-gateway/MASTER_KEY", "/run/sealed/secrets/llm-gateway/MASTER_KEY");
    expect(() => checkSecretMounts(secretMountsFromAppCompose(other), golden12Stack)).toThrow("notes-db mounts the secrets of llm-gateway");
    // The agent itself may bind the root and the socket.
    expect(() => secretMountsFromAppCompose(bind("sealed-agent", "/run/sealed", "/run/sealed-all"))).not.toThrow();
  });
});
