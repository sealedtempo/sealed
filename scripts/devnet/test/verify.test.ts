import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { sealedVerifyArgs } from "../src/verify.ts";

const value = (args: string[], flag: string) => {
  const i = args.indexOf(flag);
  return i < 0 ? undefined : args[i + 1];
};

describe("the devnet runs sealed verify the way a user on another chain does (merge C open issue)", () => {
  it("passes the deployments file, an RPC and the release asset base, and no defaults file", () => {
    const args = sealedVerifyArgs({ deploymentId: "0xab", evidence: true, rpcUrl: "http://127.0.0.1:8545", assetBase: "http://127.0.0.1:9000/releases/download" });
    expect(args.slice(0, 3)).toEqual(["verify", "--deployment", "0xab"]);
    expect(value(args, "--evidence")).toBe("evidence.json");
    expect(value(args, "--deployments")).toBe("deployments.json");
    expect(value(args, "--rpc")).toBe("http://127.0.0.1:8545");
    expect(value(args, "--release-asset-base")).toBe("http://127.0.0.1:9000/releases/download");
    expect(args).not.toContain("--defaults");
    expect(args).not.toContain("--chain-id");
  });

  it("leaves --evidence out for a live check and appends the extra flags", () => {
    const args = sealedVerifyArgs({ deploymentId: "0xab", evidence: false, rpcUrl: "http://r", assetBase: "http://a", extra: ["--live", "https://x/attest"] });
    expect(args).not.toContain("--evidence");
    expect(args.slice(-2)).toEqual(["--live", "https://x/attest"]);
  });

  it("is what the flow's verify steps run, in a directory without a defaults file", () => {
    const flow = readFileSync(new URL("../src/flow.ts", import.meta.url), "utf8");
    const start = flow.indexOf("private async sealedVerify(");
    const body = flow.slice(start, flow.indexOf("\n  }\n", start));
    expect(start).toBeGreaterThan(0);
    expect(body).toContain("sealedVerifyArgs(");
    expect(body).not.toContain("defaults.yaml");
  });
});
