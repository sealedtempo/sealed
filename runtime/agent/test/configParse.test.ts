// The agent reads its public config by the composer's rules (@sealed/core parseSealedConfig, fix-parity). Before, its
// twin was looser and stricter in places: it refused a relay the composer accepts (endpoints.relay and relayAttest
// on an explicit :443, compared by WHATWG origin), so such a stack composed and was approved but the agent refused
// its config at boot, and outside dev sim mode it let a plain-http loopback endpoint through.
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { canonicalize, configHash } from "@sealed/core";
import { describe, expect, it } from "vitest";
import { parsePublicConfig } from "../src/context.js";
import { makeConfig } from "./helpers/fixtures.js";

const golden = await readFile(join(import.meta.dirname, "fixtures/composer-golden/config.json"), "utf8");
const goldenConfig = JSON.parse(golden) as { endpoints: Record<string, string> };
const withEndpoints = (endpoints: Record<string, string>) => canonicalize({ ...goldenConfig, endpoints: { ...goldenConfig.endpoints, ...endpoints } });

describe("the agent's public config is the composer's", () => {
  it("reads the composer's golden config, its normalized form hashing to the same configHash", () => {
    const { config, json } = parsePublicConfig(golden);
    expect(configHash(config)).toBe(configHash(json));
  });

  it("accepts a relay on an explicit port 443, as the composer does", () => {
    const text = withEndpoints({ relay: "https://attest.relay.sealed.example:443", relayAttest: "https://attest.relay.sealed.example:443/attest" });
    expect(parsePublicConfig(text).config.endpoints.relay).toBe("https://attest.relay.sealed.example:443");
    // One side on :443 and the other without is two hosts to the composer (D-045).
    expect(() => parsePublicConfig(withEndpoints({ relayAttest: "https://attest.relay.sealed.example:443/attest" }))).toThrow("endpoints.relay");
  });

  it("refuses plain http and loopback endpoints outside dev sim mode, accepts them in it", () => {
    const local = canonicalize(makeConfig());
    expect(() => parsePublicConfig(local)).toThrow("invalid public config: config: endpoints.keyBroker");
    expect(parsePublicConfig(local, { devSim: true }).config.endpoints.keyBroker).toBe("http://127.0.0.1:9");
    expect(() => parsePublicConfig(withEndpoints({ tempoRpc: "https://127.0.0.1:8545" }))).toThrow("endpoints.tempoRpc");
  });

  it("refuses what only the composer used to refuse", () => {
    expect(() => parsePublicConfig(withEndpoints({ relayAttest: "https://attest.relay.sealed.example/v1/attest" }))).toThrow("endpoints.relayAttest");
    expect(() => parsePublicConfig(canonicalize({ ...goldenConfig, allowedVpcRanges: ["172.30.128.0/20"] }))).toThrow("allowedVpcRanges[0]");
    expect(() => parsePublicConfig(canonicalize({ ...goldenConfig, extra: true }))).toThrow("extra");
  });
});
