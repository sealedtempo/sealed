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
    expect(agentSecretOwners(mounts)).toBeUndefined();
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
    const appRoot = variant((svcs) => {
      svcs["notes-web"]?.volumes.push(bind("/run/sealed/secrets"));
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
    expect(() => secretMountsFromAppCompose(foreignSource)).toThrow("secret binds must use the same host path");
    const wrongVolume = variant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets-llm-gateway", target: "/run/sealed/secrets/notes/X", read_only: true });
    });
    expect(() => secretMountsFromAppCompose(wrongVolume)).toThrow("not sealed-secrets-notes");
    const wrongSubpath = variant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets-notes", target: "/run/sealed/secrets/notes/X", read_only: true, volume: { subpath: "Y" } });
    });
    expect(() => secretMountsFromAppCompose(wrongSubpath)).toThrow("subpath Y");
    const deep = variant((svcs) => {
      svcs["notes-web"]?.volumes.push(bind("/run/sealed/secrets/notes/A/B"));
    });
    expect(() => secretMountsFromAppCompose(deep)).toThrow("not /run/sealed/secrets/<owner>[/<NAME>]");
  });
});
