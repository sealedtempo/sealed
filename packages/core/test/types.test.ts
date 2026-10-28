import { describe, expect, it } from "vitest";
import {
  evidenceBundleSchema,
  releasePlaintextSchema,
  routeHostname,
  sealedConfigSchema,
  usageEventSchema,
} from "../src/types/index.js";

export const exampleConfig = {
  schema: "sealed-config/v1",
  chainId: 4217,
  customer: "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
  salt: `0x${"5a".repeat(32)}`,
  imageId: `0x${"1d".repeat(32)}`,
  composerVersion: "1.0.0",
  apps: [
    { id: "crm", releaseId: `0x${"c1".repeat(32)}` },
    { id: "llm-gateway", releaseId: `0x${"11".repeat(32)}` },
  ],
  hostnames: { scheme: "sslip", ip: "34.1.2.3" },
  egressAdditions: { scraper: ["example.com:443", "*.example.org:443"] },
  allowedVpcRanges: [],
  endpoints: {
    keyBroker: "https://sealed-key-broker-xyz.a.run.app",
    platformApi: "https://api.example",
    tempoRpc: "https://rpc.tempo.xyz",
    relay: "https://attest.relay.example",
    relayAttest: "https://attest.relay.example/attest",
  },
  contracts: {
    platformRegistry: `0x${"01".repeat(20)}`,
    appRegistry: `0x${"02".repeat(20)}`,
    deploymentRegistry: `0x${"03".repeat(20)}`,
    feeSplitter: `0x${"04".repeat(20)}`,
  },
  feeToken: "0x20c0000000000000000000000000000000000000",
  settlement: { mode: "access-key", intervalMinutes: 60, gracePeriodMinutes: 1440, spendLimitPerDay: "2000000" },
  relayOwner: `0x${"05".repeat(20)}`,
};

describe("sealed-config/v1", () => {
  it("accepts the INTERFACES example", () => {
    expect(sealedConfigSchema.parse(exampleConfig).settlement.mode).toBe("access-key");
  });
  it("defaults debug to false, so configHash is over the composer's normalized form", () => {
    expect(sealedConfigSchema.parse(exampleConfig).debug).toBe(false);
    expect(sealedConfigSchema.parse({ ...exampleConfig, debug: true }).debug).toBe(true);
    expect(sealedConfigSchema.safeParse({ ...exampleConfig, debug: "yes" }).success).toBe(false);
  });
  it("with llm-gateway, serves the relay on the attest origin (D-045)", () => {
    const relay = (r: string) => ({ ...exampleConfig, endpoints: { ...exampleConfig.endpoints, relay: r } });
    expect(sealedConfigSchema.safeParse(relay("https://relay.example")).success).toBe(false);
    expect(sealedConfigSchema.safeParse(relay("https://attest.relay.example/")).success).toBe(false);
    const noGateway = { ...relay("https://relay.example"), apps: [{ id: "crm", releaseId: `0x${"c1".repeat(32)}` }] };
    expect(sealedConfigSchema.safeParse(noGateway).success).toBe(true);
  });
  it("requires apps sorted by id", () => {
    const bad = { ...exampleConfig, apps: [...exampleConfig.apps].reverse() };
    expect(sealedConfigSchema.safeParse(bad).success).toBe(false);
  });
  it("rejects a bad settlement mode and float money", () => {
    expect(sealedConfigSchema.safeParse({ ...exampleConfig, settlement: { ...exampleConfig.settlement, mode: "card" } }).success).toBe(false);
    expect(sealedConfigSchema.safeParse({ ...exampleConfig, settlement: { ...exampleConfig.settlement, spendLimitPerDay: "2.5" } }).success).toBe(false);
  });
  it("derives route hostnames", () => {
    const cfg = sealedConfigSchema.parse(exampleConfig);
    expect(routeHostname(cfg, "attest")).toBe("attest.34-1-2-3.sslip.io");
    const custom = sealedConfigSchema.parse({ ...exampleConfig, hostnames: { scheme: "custom", domains: { attest: "attest.example.com" } } });
    expect(routeHostname(custom, "attest")).toBe("attest.example.com");
    expect(routeHostname(custom, "crm")).toBeUndefined();
  });
});

describe("other schemas", () => {
  it("release plaintext", () => {
    const ok = { secrets: { crm: { APP_SECRET: "x" }, _gate: { GATE_PASSWORD_BCRYPT: "$2a$" } }, diskKey: `0x${"00".repeat(32)}`, signerSeed: `0x${"01".repeat(32)}` };
    expect(releasePlaintextSchema.parse(ok).secrets.crm?.APP_SECRET).toBe("x");
    expect(releasePlaintextSchema.safeParse({ ...ok, secrets: { "../etc": { X: "1" } } }).success).toBe(false);
    expect(releasePlaintextSchema.safeParse({ ...ok, secrets: { crm: { "bad name": "1" } } }).success).toBe(false);
  });
  it("usage events", () => {
    expect(usageEventSchema.parse({ app: "llm-gateway", unit: "tokens", quantity: 123, meta: { model: "m" } }).quantity).toBe(123);
    expect(usageEventSchema.safeParse({ app: "llm-gateway", unit: "tokens", quantity: 1.5 }).success).toBe(false);
    expect(usageEventSchema.safeParse({ app: "llm-gateway", unit: "bytes", quantity: 1 }).success).toBe(false);
  });
  it("evidence bundle", () => {
    const bundle = {
      schema: "sealed-evidence/v1",
      chainId: 4217,
      contracts: exampleConfig.contracts,
      deploymentId: `0x${"aa".repeat(32)}`,
      customer: exampleConfig.customer,
      imageId: exampleConfig.imageId,
      releaseIds: exampleConfig.apps.map((a) => a.releaseId),
      config: exampleConfig,
      configHash: `0x${"bb".repeat(32)}`,
      appCompose: "{}",
      stackHash: `0x${"cc".repeat(32)}`,
      enclaveSigner: `0x${"dd".repeat(20)}`,
      nonce2: `0x${"ee".repeat(32)}`,
      attestedAt: 1730000000,
      quote: "0x00",
      quoteHash: `0x${"ff".repeat(32)}`,
      eventLog: [{ imr: 3, event_type: 134217729, digest: "00", event: "compose-hash", event_payload: "00" }],
      eventLogHash: `0x${"12".repeat(32)}`,
      runtime: "dstack",
    };
    expect(evidenceBundleSchema.parse(bundle).runtime).toBe("dstack");
    expect(evidenceBundleSchema.safeParse({ ...bundle, attestedAt: -1 }).success).toBe(false);
  });
});
