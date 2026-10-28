import { bcryptVerify } from "@sealed/agent/dist/src/gate/bcrypt.js";
import { describe, expect, it } from "vitest";
import { generate, manifestSecrets, planSecrets } from "../src/secrets.ts";
import { ustar } from "./helpers.ts";

const bundle = (manifest: string) => ustar({ "manifest.yaml": manifest, "compose.fragment.yaml": "services: {}\n", "egress.yaml": "version: 1\n" });

describe("secret plan for the devnet key broker", () => {
  it("generates required secrets, resolves same_as, leaves optional ones unset and stores the gate hash", () => {
    const gw = bundle(`id: gw
secrets:
  - name: MASTER
    generate: sk-hex32
  - name: APP_KEY
    generate: hex32
  - name: BYOK
    generate: none
    optional: true
`);
    const app = bundle(`id: app
secrets:
  - name: GW_KEY
    generate: none
    same_as: gw/APP_KEY
  - name: ADMIN_EMAIL
    generate: none
  - name: ADMIN_PASSWORD
    generate: password
`);
    expect(manifestSecrets(app).id).toBe("app");
    const p = planSecrets([gw, app]);
    expect(Object.keys(p.store).sort()).toEqual(["sealed-app-ADMIN_EMAIL", "sealed-app-ADMIN_PASSWORD", "sealed-gate-password", "sealed-gw-APP_KEY", "sealed-gw-MASTER"]);
    expect(p.expected.app?.GW_KEY).toBe(p.store["sealed-gw-APP_KEY"]);
    expect(p.expected.gw?.MASTER).toMatch(/^sk-[0-9a-f]{64}$/);
    expect(p.expected.app?.ADMIN_PASSWORD).toMatch(/^[A-Za-z0-9]{24}$/);
    expect(p.expected.app?.ADMIN_EMAIL).toBe("admin@devnet.sealed.example");
    expect(p.unset).toEqual({ gw: ["BYOK"] });
    expect(bcryptVerify(new TextEncoder().encode(p.gatePassword), p.store["sealed-gate-password"] as string)).toBe(true);
  });

  it("refuses a required same_as to a secret nobody stores", () => {
    const app = bundle(`id: app
secrets:
  - name: K
    generate: none
    same_as: other/K
`);
    expect(() => planSecrets([app])).toThrow("same_as other/K");
  });

  it("formats each generator", () => {
    expect(generate("hex32", "X")).toMatch(/^[0-9a-f]{64}$/);
    expect(Buffer.from(generate("base64-32", "X"), "base64")).toHaveLength(32);
    expect(generate(undefined, "TOKEN")).toBe("devnet-token");
  });
});
