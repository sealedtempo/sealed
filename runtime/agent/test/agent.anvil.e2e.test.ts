// The whole agent against the dstack simulator, a fake key broker, a fake platform, and a local
// Tempo node with the Sealed contracts: the oracle registers the record built from the agent's
// evidence bundle, the customer authorizes the enclave signer as an access key, and the agent's
// own settlement loop pays FeeSplitter.
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type Address,
  appId as computeAppId,
  feeSplitterAbi,
  type Hex,
  imageId as computeImageId,
  loadDefaults,
  measurementsHash,
  releaseId as computeReleaseId,
  SIM_MEASUREMENTS,
  tempoChain,
} from "@sealed/core";
import {
  addImage,
  approveStack,
  chainTestsEnabled,
  DEV_KEYS,
  deploySealedContracts,
  devAddress,
  LOCAL_TOKENS,
  type LocalTempo,
  publishRelease,
  registerApp,
  registerDeployment,
  type SealedDeployment,
  startLocalTempo,
} from "@sealed/core/testing";
import { http, parseEventLogs, toFunctionSelector } from "viem";
import { Abis, Account, Addresses, createClient } from "viem/tempo";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent } from "../src/agent.js";
import { DstackClient } from "../src/dstack.js";
import { localRequest, parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import { fixedTlsKey } from "../src/tls.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { startFakeCaddy, type FakeCaddy } from "./helpers/fakeCaddy.js";
import { type FakePlatform, startFakePlatform } from "./helpers/fakePlatform.js";
import { CADDYFILE, fromPeer, IPS, makeAppCompose, makeConfig, testPeerOf, testSettings } from "./helpers/fixtures.js";

const enabled = chainTestsEnabled();

describe.skipIf(!enabled)("sealed-agent end to end on a local Tempo node", () => {
  let node: LocalTempo;
  let d: SealedDeployment;
  let dir: string;
  let broker: FakeBroker;
  let platform: FakePlatform;
  let caddy: FakeCaddy;
  let sim: RunningSimulator;
  let agent: Agent;
  const customerKey = DEV_KEYS.customer;
  const customer = devAddress(customerKey);
  const m = {
    mrtd: `0x${SIM_MEASUREMENTS.mrtd}` as Hex,
    rtmr0: `0x${SIM_MEASUREMENTS.rtmr0}` as Hex,
    rtmr1: `0x${SIM_MEASUREMENTS.rtmr1}` as Hex,
    rtmr2: `0x${SIM_MEASUREMENTS.rtmr2}` as Hex,
  };
  const imageId = computeImageId("sealed-sim", "1.0.0", measurementsHash(m.mrtd, m.rtmr0, m.rtmr1, m.rtmr2));
  const crm = computeAppId("crm");
  const llm = computeAppId("llm-gateway");
  const releases = { crm: computeReleaseId(crm, "1.0.0", `0x${"c1".repeat(32)}`), llm: computeReleaseId(llm, "1.0.0", `0x${"11".repeat(32)}`) };
  const clock = { now: () => Math.floor(Date.now() / 1000), sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, Math.min(ms, 20))) };

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-agent-chain-"));
    node = await startLocalTempo();
    d = await deploySealedContracts(node);
    await addImage(node, d, { imageId, name: "sealed-sim", version: "1.0.0", ...m });
    await registerApp(node, d, { appId: crm, slug: "crm", shareBps: 5000 });
    await registerApp(node, d, { appId: llm, slug: "llm-gateway", shareBps: 2000 });
    await publishRelease(node, d, { appId: crm, version: "1.0.0", bundleHash: `0x${"c1".repeat(32)}` });
    await publishRelease(node, d, { appId: llm, version: "1.0.0", bundleHash: `0x${"11".repeat(32)}` });

    broker = await startFakeBroker({ customer, secrets: { crm: { APP_SECRET: "x" } } });
    platform = await startFakePlatform();
    caddy = await startFakeCaddy(join(dir, "caddy-admin.sock"), CADDYFILE);
    const config = makeConfig({
      chainId: node.chainId,
      customer,
      imageId,
      apps: [
        { id: "crm", releaseId: releases.crm },
        { id: "llm-gateway", releaseId: releases.llm },
      ],
      endpoints: { keyBroker: broker.url, platformApi: platform.url, tempoRpc: node.rpcUrl },
      contracts: { platformRegistry: d.platformRegistry, appRegistry: d.appRegistry, deploymentRegistry: d.deploymentRegistry, feeSplitter: d.feeSplitter },
      feeToken: LOCAL_TOKENS.pathUsd,
      settlement: { mode: "access-key", intervalMinutes: 5, gracePeriodMinutes: 5, spendLimitPerDay: "2000000" },
    });
    const appCompose = makeAppCompose(config);
    await writeFile(join(dir, "config.json"), JSON.stringify(config));
    sim = await startSimulator({ appCompose, socket: join(dir, "dstack.sock") });
    agent = new Agent({
      settings: testSettings(dir, { testOverrides: true, dstackEndpoint: sim.endpoint }),
      peerOf: testPeerOf,
      clock,
      log: silentLogger,
      dstack: new DstackClient(parseEndpoint(sim.endpoint)),
      tls: fixedTlsKey(`0x${"77".repeat(32)}`),
      egressStats: async () => undefined,
      defaults: await loadDefaults(join(import.meta.dirname, "../../../config/defaults.yaml"), { testOverrides: true }),
    });
    await agent.boot();
    await agent.evidence;
  }, 180_000);

  afterAll(async () => {
    await agent?.stop();
    await Promise.all([broker?.close(), platform?.close(), caddy?.close(), sim?.close()]);
    await node?.stop();
    await rm(dir, { recursive: true, force: true });
  });

  it("the oracle registers the deployment from the agent's evidence; the customer authorizes the enclave key; the agent pays", async () => {
    const b = platform.evidence[0];
    expect(b).toBeDefined();
    if (!b) return;
    // Customer approves exactly the stack the agent booted, then the oracle registers the record.
    await approveStack(node, d, customerKey, { stackHash: b.stackHash as Hex, releaseIds: b.releaseIds as Hex[], imageId });
    const block = await node.client.getBlock();
    await registerDeployment(node, d, {
      deploymentId: b.deploymentId as Hex,
      customer: b.customer as Address,
      stackHash: b.stackHash as Hex,
      imageId: b.imageId as Hex,
      quoteHash: b.quoteHash as Hex,
      eventLogHash: b.eventLogHash as Hex,
      configHash: b.configHash as Hex,
      enclaveSigner: b.enclaveSigner as Address,
      attestedAt: block.timestamp,
    });

    const ready = JSON.parse((await localRequest(parseEndpoint(`http://127.0.0.1:${agent.port}`), "/v1/ready")).body);
    const keyId = ready.enclaveSigner as Address;
    const chain = tempoChain({ chainId: node.chainId, rpcUrl: node.rpcUrl, feeToken: LOCAL_TOKENS.pathUsd });
    const wallet = createClient({ chain: chain as never, transport: http(node.rpcUrl), pollingInterval: 100 });
    const hash = await wallet.writeContract({
      account: Account.fromSecp256k1(customerKey),
      address: Addresses.accountKeychain,
      abi: Abis.accountKeychain,
      functionName: "authorizeKey",
      args: [
        keyId,
        0,
        {
          expiry: 2n ** 64n - 1n,
          enforceLimits: true,
          limits: [{ token: LOCAL_TOKENS.pathUsd, amount: 2_000_000n, period: 86_400n }],
          allowAnyCalls: false,
          allowedCalls: [
            { target: LOCAL_TOKENS.pathUsd, selectorRules: [{ selector: toFunctionSelector("approve(address,uint256)"), recipients: [d.feeSplitter] }] },
            {
              target: d.feeSplitter,
              selectorRules: [
                { selector: toFunctionSelector("payFees(bytes32,bytes32,address,uint256,bytes32)"), recipients: [] },
                { selector: toFunctionSelector("topUpFees(bytes32,bytes32,address,uint256,bytes32)"), recipients: [] },
              ],
            },
          ],
        },
      ],
      feeToken: LOCAL_TOKENS.pathUsd,
      gas: 5_000_000n,
    } as never);
    expect((await wallet.waitForTransactionReceipt({ hash, timeout: 10_000 })).status).toBe("success");

    const ep = parseEndpoint(`http://127.0.0.1:${agent.port}`);
    expect((await localRequest(ep, "/v1/usage-events", { body: { app: "llm-gateway", unit: "tokens", quantity: 2_500_000 }, headers: fromPeer(IPS.llm) })).status).toBe(202);
    const result = await agent.settle();
    expect(result.outcome).toBe("settled");
    const paid = result.apps[0] as Extract<(typeof result.apps)[number], { result: "paid" }>;
    expect(paid).toMatchObject({ app: "llm-gateway", result: "paid", amount: 500_000n });
    const receipt = await node.client.getTransactionReceipt({ hash: paid.txHash });
    const [ev] = parseEventLogs({ abi: feeSplitterAbi, logs: receipt.logs, eventName: "FeesPaid" });
    expect(ev?.args.deploymentId).toBe(b.deploymentId);
    expect(ev?.args.payer.toLowerCase()).toBe(customer);
    expect(platform.usage.length).toBe(1);
    expect(agent.store?.state.payments.lastOutcome).toBe("settled");
  });
});
