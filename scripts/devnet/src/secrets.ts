// The customer's secrets for the devnet key broker's in-memory store (its --dev-secrets-file), planned from the
// manifests in the stack's release bundles like `sealed secrets set --missing` does: every required secret gets a
// value from its generator, a same_as secret is stored once under the app it names (D-043), optional secrets stay
// unset, and the gate password is stored as its bcrypt hash (sealed-gate-password).
import { randomBytes } from "node:crypto";
import { bcryptHash } from "@sealed/agent/dist/src/gate/bcrypt.js";
import { parse as parseYaml } from "yaml";
import { readTar } from "./assets.ts";

export interface ManifestSecret {
  name: string;
  generate?: string;
  optional?: boolean;
  same_as?: string;
}

export function manifestSecrets(bundle: Uint8Array): { id: string; secrets: ManifestSecret[] } {
  const raw = readTar(bundle).get("manifest.yaml");
  if (!raw) throw new Error("bundle has no manifest.yaml");
  const m = parseYaml(new TextDecoder().decode(raw)) as { id: string; secrets?: ManifestSecret[] };
  return { id: m.id, secrets: m.secrets ?? [] };
}

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

export function generate(kind: string | undefined, name: string): string {
  switch (kind) {
    case "hex32":
      return randomBytes(32).toString("hex");
    case "base64-32":
      return randomBytes(32).toString("base64");
    case "sk-hex32":
      return `sk-${randomBytes(32).toString("hex")}`;
    case "password": {
      // 24 characters from [A-Za-z0-9] without modulo bias (62 * 4 = 248 < 256).
      let out = "";
      while (out.length < 24) for (const b of randomBytes(32)) if (b < 248 && out.length < 24) out += ALNUM[b % 62];
      return out;
    }
    default:
      // generate: none (the customer types it): a recognizable devnet value.
      return name.toLowerCase().includes("email") ? "admin@devnet.sealed.example" : `devnet-${name.toLowerCase()}`;
  }
}

export interface SecretPlan {
  /** Secret Manager style names -> values: the broker's dev secrets file. */
  store: Record<string, string>;
  /** What each app must receive: app -> NAME -> value (same_as resolved). Optional unset secrets are absent. */
  expected: Record<string, Record<string, string>>;
  /** Optional secrets left unset: app -> names. */
  unset: Record<string, string[]>;
  gatePassword: string;
}

export function planSecrets(bundles: Uint8Array[]): SecretPlan {
  const manifests = bundles.map(manifestSecrets);
  const store: Record<string, string> = {};
  const expected: Record<string, Record<string, string>> = {};
  const unset: Record<string, string[]> = {};
  for (const m of manifests) {
    expected[m.id] = {};
    for (const s of m.secrets) {
      if (s.same_as || s.optional) continue;
      const v = generate(s.generate, s.name);
      store[`sealed-${m.id}-${s.name}`] = v;
      (expected[m.id] as Record<string, string>)[s.name] = v;
    }
  }
  for (const m of manifests) {
    for (const s of m.secrets) {
      if (s.same_as) {
        const [app, name] = s.same_as.split("/");
        const v = store[`sealed-${app}-${name}`];
        if (v === undefined) {
          if (s.optional) continue;
          throw new Error(`${m.id}/${s.name}: same_as ${s.same_as} names a secret that is not stored`);
        }
        (expected[m.id] as Record<string, string>)[s.name] = v;
      } else if (s.optional) {
        (unset[m.id] ??= []).push(s.name);
      }
    }
  }
  const gatePassword = generate("password", "gate");
  store["sealed-gate-password"] = bcryptHash(new TextEncoder().encode(gatePassword), randomBytes(16), 10);
  return { store, expected, unset, gatePassword };
}
