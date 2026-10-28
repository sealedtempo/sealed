import { describe, expect, it } from "vitest";
import { bundleAssetPath, readTar, sha256Hex, startAssetServer } from "../src/assets.ts";
import { ustar } from "./helpers.ts";

describe("release asset host (D-046)", () => {
  it("serves a bundle at <base>/<appId>-v<version>/<appId>-<version>.bundle.tar", async () => {
    expect(bundleAssetPath("crm", "10.0.11")).toBe("/crm-v10.0.11/crm-10.0.11.bundle.tar");
    // A manifest version that already starts with v keeps it: the tag is <appId>-v<release_version>.
    expect(bundleAssetPath("coding-agent", "v1.58.2")).toBe("/coding-agent-vv1.58.2/coding-agent-v1.58.2.bundle.tar");
    expect(() => bundleAssetPath("crm", "1.0.0+build.1")).toThrow("cannot name release assets");
    expect(() => bundleAssetPath("Crm", "1.0.0")).toThrow("not a catalog slug");

    const srv = await startAssetServer();
    try {
      const bytes = new TextEncoder().encode("bundle bytes");
      const url = srv.add("crm", "10.0.11", bytes);
      expect(url).toBe(`${srv.base}/crm-v10.0.11/crm-10.0.11.bundle.tar`);
      expect(srv.base).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/sealedtempo\/sealed\/releases\/download$/);
      const ok = await fetch(url);
      expect(ok.status).toBe(200);
      expect(sha256Hex(new Uint8Array(await ok.arrayBuffer()))).toBe(sha256Hex(bytes));
      expect((await fetch(`${srv.base}/crm-v10.0.12/crm-10.0.12.bundle.tar`)).status).toBe(404);
      expect((await fetch(url, { method: "POST" })).status).toBe(404);
      expect(srv.hits.map((h) => h.status)).toEqual([200, 404, 404]);
    } finally {
      await srv.close();
    }
  });

  it("reads the files of a ustar bundle", () => {
    const tar = ustar({ "manifest.yaml": "id: crm\n", "LICENSES/AGPL.txt": "x".repeat(700), "egress.yaml": "" });
    const files = readTar(tar);
    expect([...files.keys()]).toEqual(["LICENSES/AGPL.txt", "egress.yaml", "manifest.yaml"]);
    expect(new TextDecoder().decode(files.get("manifest.yaml"))).toBe("id: crm\n");
    expect(files.get("LICENSES/AGPL.txt")?.length).toBe(700);
    expect(files.get("egress.yaml")?.length).toBe(0);
    expect(() => readTar(tar.slice(0, 600))).toThrow("truncated");
  });
});
