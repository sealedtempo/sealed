import { hashTypedData, keccak256, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import {
  type DeploymentRecord,
  HEARTBEAT_TYPEHASH,
  heartbeatDigest,
  heartbeatTypes,
  RECORD_TYPEHASH,
  recordDigest,
  recordTypes,
  recoverUsageReportSigner,
  registryDomain,
  signUsageReport,
  type UsageReport,
  UsageUnit,
  usageDomain,
  usageReportDigest,
  usageReportFromJson,
  usageReportToJson,
  usageReportTypes,
} from "../src/eip712.js";
import { appId } from "../src/ids.js";

const registry = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const splitter = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512";
const record: DeploymentRecord = {
  deploymentId: `0x${"01".repeat(32)}`,
  customer: "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
  stackHash: `0x${"02".repeat(32)}`,
  imageId: `0x${"03".repeat(32)}`,
  quoteHash: `0x${"04".repeat(32)}`,
  eventLogHash: `0x${"05".repeat(32)}`,
  configHash: `0x${"06".repeat(32)}`,
  enclaveSigner: "0x976ea74026e726554db657fa54763abd0c3a0aa9",
  attestedAt: 1_793_000_000n,
};
const report: UsageReport = {
  deploymentId: `0x${"01".repeat(32)}`,
  periodStart: 1_793_000_000n,
  periodEnd: 1_793_003_600n,
  items: [
    { appId: appId("crm"), unit: UsageUnit.app_hour, quantity: 3600n, fee: 50_000n },
    { appId: appId("llm-gateway"), unit: UsageUnit.tokens, quantity: 1_234_567n, fee: 246_913n },
  ],
};

describe("EIP-712 typehashes match the contracts", () => {
  it("Record and Heartbeat", () => {
    expect(RECORD_TYPEHASH).toBe(
      keccak256(
        toBytes(
          "Record(bytes32 deploymentId,address customer,bytes32 stackHash,bytes32 imageId,bytes32 quoteHash,bytes32 eventLogHash,bytes32 configHash,address enclaveSigner,uint64 attestedAt)",
        ),
      ),
    );
    expect(HEARTBEAT_TYPEHASH).toBe(keccak256(toBytes("Heartbeat(bytes32 deploymentId,bytes32 quoteHash,uint64 attestedAt)")));
  });
});

describe("hand-encoded digests equal viem hashTypedData", () => {
  for (const chainId of [4217, 31337]) {
    it(`Record on chain ${chainId}`, () => {
      const domain = registryDomain(registry, chainId);
      expect(recordDigest(record, domain)).toBe(hashTypedData({ domain, types: recordTypes, primaryType: "Record", message: record }));
    });
    it(`Heartbeat on chain ${chainId}`, () => {
      const domain = registryDomain(registry, chainId);
      const hb = { deploymentId: record.deploymentId, quoteHash: record.quoteHash, attestedAt: record.attestedAt };
      expect(heartbeatDigest(hb, domain)).toBe(hashTypedData({ domain, types: heartbeatTypes, primaryType: "Heartbeat", message: hb }));
    });
    it(`UsageReport on chain ${chainId}`, () => {
      const domain = usageDomain(splitter, chainId);
      expect(usageReportDigest(report, domain)).toBe(
        hashTypedData({ domain, types: usageReportTypes, primaryType: "UsageReport", message: report }),
      );
    });
  }
  it("an empty item list still hashes", () => {
    const domain = usageDomain(splitter);
    const empty = { ...report, items: [] };
    expect(usageReportDigest(empty, domain)).toBe(
      hashTypedData({ domain, types: usageReportTypes, primaryType: "UsageReport", message: empty }),
    );
  });
  it("domains bind name, chain and contract", () => {
    expect(recordDigest(record, registryDomain(registry, 4217))).not.toBe(recordDigest(record, registryDomain(registry, 1)));
    expect(usageReportDigest(report, usageDomain(splitter))).not.toBe(usageReportDigest(report, usageDomain(registry)));
  });
});

describe("usage report signatures", () => {
  const key = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba" as const;
  it("signs with the enclave key and recovers the signer", async () => {
    const domain = usageDomain(splitter);
    const sig = await signUsageReport(report, domain, key);
    expect(await recoverUsageReportSigner(report, domain, sig)).toBe(privateKeyToAccount(key).address);
    const tampered = { ...report, items: [{ ...(report.items[0] as (typeof report.items)[0]), fee: 1n }] };
    expect(await recoverUsageReportSigner(tampered, domain, sig)).not.toBe(privateKeyToAccount(key).address);
  });
  it("JSON form round-trips with decimal strings", () => {
    const json = usageReportToJson(report);
    expect(json.items[1]?.quantity).toBe("1234567");
    expect(usageReportFromJson(JSON.parse(JSON.stringify(json)))).toEqual(report);
  });
});
