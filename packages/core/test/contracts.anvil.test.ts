// Cross-checks the EIP-712 helpers against DeploymentRegistry.recordDigest / heartbeatDigest on a
// local Tempo node with the contracts deployed. Skipped when anvil or the contracts are missing (fails
// instead with SEALED_REQUIRE_CHAIN_TESTS=1).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type DeploymentRecord, HEARTBEAT_TYPEHASH, heartbeatDigest, RECORD_TYPEHASH, recordDigest, registryDomain } from "../src/eip712.js";
import { deploymentId as computeDeploymentId, measurementsHash } from "../src/ids.js";
import {
  chainTestsEnabled,
  deploySealedContracts,
  type LocalTempo,
  type SealedDeployment,
  startLocalTempo,
} from "../src/testing/index.js";

const enabled = chainTestsEnabled();

describe.skipIf(!enabled)("EIP-712 digests against the deployed DeploymentRegistry", () => {
  let node: LocalTempo;
  let d: SealedDeployment;
  beforeAll(async () => {
    node = await startLocalTempo();
    d = await deploySealedContracts(node);
  }, 120_000);
  afterAll(async () => node?.stop());

  const record: DeploymentRecord = {
    deploymentId: computeDeploymentId("0x90f79bf6eb2c4f870365e785982e1f101e93b906", `0x${"02".repeat(32)}`, `0x${"03".repeat(32)}`),
    customer: "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
    stackHash: `0x${"02".repeat(32)}`,
    imageId: `0x${"04".repeat(32)}`,
    quoteHash: `0x${"05".repeat(32)}`,
    eventLogHash: `0x${"06".repeat(32)}`,
    configHash: `0x${"07".repeat(32)}`,
    enclaveSigner: "0x976ea74026e726554db657fa54763abd0c3a0aa9",
    attestedAt: 1_793_000_123n,
  };

  it("typehash constants", async () => {
    const read = (functionName: string) =>
      node.client.readContract({ address: d.deploymentRegistry, abi: d.abis.DeploymentRegistry, functionName, args: [] });
    expect(await read("RECORD_TYPEHASH")).toBe(RECORD_TYPEHASH);
    expect(await read("HEARTBEAT_TYPEHASH")).toBe(HEARTBEAT_TYPEHASH);
  });

  it("recordDigest", async () => {
    const onchain = await node.client.readContract({
      address: d.deploymentRegistry,
      abi: d.abis.DeploymentRegistry,
      functionName: "recordDigest",
      args: [record],
    });
    expect(onchain).toBe(recordDigest(record, registryDomain(d.deploymentRegistry, node.chainId)));
  });

  it("heartbeatDigest", async () => {
    const onchain = await node.client.readContract({
      address: d.deploymentRegistry,
      abi: d.abis.DeploymentRegistry,
      functionName: "heartbeatDigest",
      args: [record.deploymentId, record.quoteHash, record.attestedAt],
    });
    const local = heartbeatDigest(
      { deploymentId: record.deploymentId, quoteHash: record.quoteHash, attestedAt: record.attestedAt },
      registryDomain(d.deploymentRegistry, node.chainId),
    );
    expect(onchain).toBe(local);
  });

  it("measurementsHash equals PlatformRegistry.computeMeasurementsHash", async () => {
    const m = [`0x${"11".repeat(48)}`, `0x${"22".repeat(48)}`, `0x${"33".repeat(48)}`, `0x${"44".repeat(48)}`] as const;
    const onchain = await node.client.readContract({
      address: d.platformRegistry,
      abi: d.abis.PlatformRegistry,
      functionName: "computeMeasurementsHash",
      args: [...m],
    });
    expect(onchain).toBe(measurementsHash(...m));
  });
});
