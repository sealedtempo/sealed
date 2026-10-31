import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { sealedVerifyArgs } from "../src/verifyArgs.ts";

// merge-c-final: sealed verify needs only the chain's deployments file, its RPC and the asset base on another chain;
// the devnet still wrote a defaults file for it. The verify steps of make devnet-e2e run this command line.
describe("the devnet's sealed verify command line", () => {
  const args = sealedVerifyArgs({ deployment: "dep_abcdefgh", evidence: true, rpcUrl: "http://127.0.0.1:8545", assetBase: "http://127.0.0.1:9000/releases/download", extra: ["--live", "https://x"] });
  const value = (flag: string) => args[args.indexOf(flag) + 1];

  it("names the deployments file, the RPC and the asset base, and no defaults file", () => {
    expect(args.slice(0, 3)).toEqual(["verify", "--deployment", "dep_abcdefgh"]);
    expect(value("--deployments")).toBe("deployments.json");
    expect(value("--rpc")).toBe("http://127.0.0.1:8545");
    expect(value("--release-asset-base")).toBe("http://127.0.0.1:9000/releases/download");
    expect(value("--evidence")).toBe("evidence.json");
    expect(args).not.toContain("--defaults");
    expect(args.slice(-2)).toEqual(["--live", "https://x"]);
    expect(sealedVerifyArgs({ deployment: "0x01", evidence: false, rpcUrl: "r", assetBase: "a" })).not.toContain("--evidence");
  });

  it("flow.ts runs it and writes no defaults file for verify", () => {
    const flow = readFileSync(new URL("../src/flow.ts", import.meta.url), "utf8");
    const body = flow.slice(flow.indexOf("private async sealedVerify("), flow.indexOf("private async stepVerify("));
    expect(body).toContain("sealedVerifyArgs(");
    expect(body).not.toMatch(/defaults/i);
  });
});
