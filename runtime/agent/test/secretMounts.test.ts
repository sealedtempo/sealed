// Brief item 5 (D-042): what each service of the measured compose can see under /run/sealed/secrets,
// on the composer's golden stack (composer 1.1: whole owner directories) and on a compose that mounts
// one file per declared secret (composer 1.2).
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { canonicalize } from "@sealed/core";
import { describe, expect, it } from "vitest";
import {
  agentSecretOwners,
  checkSecretMounts,
  declaredSecretsFromAppCompose,
  filesMountedIndividually,
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

/** The golden app-compose with every app service's whole-directory mount replaced by one mount per declared secret. */
function perFileVariant(edit?: (services: Record<string, { volumes: Record<string, unknown>[] }>) => void): string {
  const outer = JSON.parse(golden);
  const compose = JSON.parse(outer.docker_compose_file);
  const declared = declaredSecretsFromAppCompose(golden);
  for (const [name, svc] of Object.entries(compose.services as Record<string, { volumes: Record<string, unknown>[] }>)) {
    if (name === "sealed-agent") continue;
    const mine = declared.filter((d) => d.service === name);
    svc.volumes = (svc.volumes ?? []).flatMap((v) => {
      const t = String(v.target);
      if (!t.startsWith("/run/sealed/secrets/") || mine.length === 0) return [v];
      return mine.map((d) => ({ type: "volume", source: v.source, target: `${t}/${d.name}`, read_only: true, volume: { nocopy: true, subpath: d.name } }));
    });
  }
  edit?.(compose.services);
  outer.docker_compose_file = canonicalize(compose);
  return canonicalize(outer);
}

describe("secret mounts in the measured compose", () => {
  it("reads the golden stack's mounts: the agent writes every owner, each service sees only its own owner", () => {
    const mounts = secretMountsFromAppCompose(golden);
    expect(mounts.filter((m) => m.service === "sealed-agent").map((m) => m.owner)).toEqual(["_gate", "llm-gateway", "notes", "sealed-mpp-payer"]);
    expect(mounts.filter((m) => m.service !== "sealed-agent")).toEqual([
      { service: "caddy", owner: "_gate", readOnly: true },
      { service: "llm-gateway-proxy", owner: "llm-gateway", readOnly: true },
      // Composer 1.1 mounts the whole notes directory into both notes services (D-042 narrows this).
      { service: "notes-db", owner: "notes", readOnly: true },
      { service: "notes-web", owner: "notes", readOnly: true },
      { service: "sealed-mpp-payer", owner: "sealed-mpp-payer", readOnly: true },
    ]);
    expect(() => checkSecretMounts(mounts, goldenStack)).not.toThrow();
    expect(filesMountedIndividually(mounts).size).toBe(0);
    expect([...(agentSecretOwners(mounts) ?? [])]).toEqual(["_gate", "llm-gateway", "notes", "sealed-mpp-payer"]);
  });

  it("lets only the agent mount the whole secrets root", () => {
    const agentRoot = perFileVariant((svcs) => {
      svcs["sealed-agent"]?.volumes.push({ type: "volume", source: "sealed-secrets", target: "/run/sealed/secrets" });
    });
    const mounts = secretMountsFromAppCompose(agentRoot);
    // The agent then writes the owners other services mount; nothing mounts `_gate` here, but caddy does in 1.1.
    expect([...agentSecretOwners(mounts)].sort()).toEqual(["_gate", "llm-gateway", "notes", "sealed-mpp-payer"]);
    expect(() => checkSecretMounts(mounts, goldenStack)).not.toThrow();
    const appRoot = perFileVariant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets", target: "/run/sealed/secrets/", read_only: true });
    });
    expect(() => checkSecretMounts(secretMountsFromAppCompose(appRoot), goldenStack)).toThrow("notes-web mounts every owner's secrets");
  });

  it("reads the declared secrets from the envexec flags", () => {
    expect(declaredSecretsFromAppCompose(golden)).toEqual(
      expect.arrayContaining([
        { service: "caddy", app: "_gate", name: "GATE_PASSWORD_BCRYPT", optional: false },
        { service: "notes-web", app: "notes", name: "SMTP_PASSWORD", optional: true },
        { service: "notes-web", app: "notes", name: "APP_SECRET", optional: false },
      ]),
    );
  });

  it("with one mount per declared secret, a service sees exactly the secrets it declares", () => {
    const compose = perFileVariant();
    const mounts = secretMountsFromAppCompose(compose);
    expect(() => checkSecretMounts(mounts, goldenStack)).not.toThrow();
    const individually = filesMountedIndividually(mounts);
    expect([...(individually.get("notes") ?? [])].sort()).toEqual(["APP_SECRET", "DB_PASSWORD", "SMTP_PASSWORD"]);
    const written = { notes: ["APP_SECRET", "DB_PASSWORD", "SMTP_PASSWORD"], "llm-gateway": ["MASTER_KEY"] };
    for (const d of declaredSecretsFromAppCompose(compose)) {
      if (d.app === "_gate") continue;
      const own = declaredSecretsFromAppCompose(compose).filter((x) => x.service === d.service).map((x) => `${x.app}/${x.name}`).sort();
      expect(visibleSecrets(mounts, d.service, written)).toEqual(own);
    }
  });

  it("refuses a service that mounts another owner's secrets, a writable mount and malformed targets", () => {
    const cross = perFileVariant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets-llm-gateway", target: "/run/sealed/secrets/llm-gateway/MASTER_KEY", read_only: true, volume: { subpath: "MASTER_KEY" } });
    });
    expect(() => checkSecretMounts(secretMountsFromAppCompose(cross), goldenStack)).toThrow("notes-web mounts the secrets of llm-gateway, but it belongs to notes");
    const sidecar = perFileVariant((svcs) => {
      (svcs["sealed-egress"] as { volumes: unknown[] }).volumes.push({ type: "volume", source: "sealed-secrets-_gate", target: "/run/sealed/secrets/_gate", read_only: true });
    });
    expect(() => checkSecretMounts(secretMountsFromAppCompose(sidecar), goldenStack)).toThrow("sealed-egress mounts the secrets of _gate");
    const writable = perFileVariant((svcs) => {
      svcs["notes-db"]?.volumes.push({ type: "volume", source: "sealed-secrets-notes", target: "/run/sealed/secrets/notes" });
    });
    expect(() => checkSecretMounts(secretMountsFromAppCompose(writable), goldenStack)).toThrow("writable");
    const wrongVolume = perFileVariant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets-llm-gateway", target: "/run/sealed/secrets/notes/X", read_only: true });
    });
    expect(() => secretMountsFromAppCompose(wrongVolume)).toThrow("not sealed-secrets-notes");
    const wrongSubpath = perFileVariant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "volume", source: "sealed-secrets-notes", target: "/run/sealed/secrets/notes/X", read_only: true, volume: { subpath: "Y" } });
    });
    expect(() => secretMountsFromAppCompose(wrongSubpath)).toThrow("subpath Y");
    const deep = perFileVariant((svcs) => {
      svcs["notes-web"]?.volumes.push({ type: "bind", source: "/x", target: "/run/sealed/secrets/notes/A/B", read_only: true });
    });
    expect(() => secretMountsFromAppCompose(deep)).toThrow("not /run/sealed/secrets/<owner>[/<NAME>]");
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
