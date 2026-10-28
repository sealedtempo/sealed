// Fee payments against a local Tempo node (anvil --network tempo, hardfork T4) with the Sealed
// contracts deployed: access-key authorization through the AccountKeychain precompile, one
// approve + payFees batch per app, FeeSplitter caps, the grace period with the payment-needed
// switch (fake Caddy admin) and recovery, a leg the customer paid short topped up to its fee,
// and the enclave-account fallback.
import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type Address,
  appId as computeAppId,
  deploymentId as computeDeploymentId,
  deriveEnclavePrivateKey,
  enclaveSignerAddress,
  feeScheduleFromDefaults,
  feeSplitterAbi,
  type Hex,
  imageId as computeImageId,
  measurementsHash,
  parseDefaults,
  releaseId as computeReleaseId,
  SIM_MEASUREMENTS,
  usageDomain,
  usageReportDigest,
  usageReportFromJson,
  type UsageReportJson,
} from "@sealed/core";
import {
  addImage,
  approveStack,
  DEV_KEYS,
  deploySealedContracts,
  devAddress,
  findContractsDir,
  fund,
  LOCAL_TOKENS,
  type LocalTempo,
  publishRelease,
  registerApp,
  registerDeployment,
  type SealedDeployment,
  startLocalTempo,
  tokenBalance,
} from "@sealed/core/testing";
import { http, parseEventLogs, toFunctionSelector } from "viem";
import { Abis, Account, Addresses, createClient as createTempoClient } from "viem/tempo";
import { tempoChain } from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { isPaymentNeededConfig, PaymentGate, SocketCaddyAdmin } from "../src/caddy.js";
import type { PlatformClient } from "../src/evidence.js";
import { parseEndpoint } from "../src/http.js";
import { createLogger, silentLogger } from "../src/log.js";
import { emptyLedgerState, Ledger } from "../src/metering/ledger.js";
import { TempoFeePayer } from "../src/payments/feePayer.js";
import { Settler } from "../src/payments/settler.js";
import type { PaymentStatus } from "../src/state.js";
import { type FakeCaddy, sampleCaddyConfig, startFakeCaddy } from "./helpers/fakeCaddy.js";

const hasAnvil = (() => {
  try {
    execFileSync("anvil", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();
const enabled = hasAnvil && !!findContractsDir();
const defaults = parseDefaults(readFileSync(join(import.meta.dirname, "../../../config/defaults.yaml"), "utf8"), { testOverrides: true });
const PATH_USD = LOCAL_TOKENS.pathUsd;
const CUSTOMER = devAddress(DEV_KEYS.customer);
const PER_PAYMENT_CAP = 1_000_000n;
const DAILY_CAP = 2_500_000n;
const KEY_LIMIT = 3_000_000n;
const testLog = process.env.TEST_LOG ? createLogger({}, { level: "debug", write: (l) => process.stderr.write(`${l}\n`) }) : silentLogger;

describe.skipIf(!enabled)("fee payments on a local Tempo node", () => {
  let node: LocalTempo;
  let d: SealedDeployment;
  let dir: string;
  let caddy: FakeCaddy;
  const image = { ...SIM_MEASUREMENTS };
  const m = { mrtd: `0x${image.mrtd}` as Hex, rtmr0: `0x${image.rtmr0}` as Hex, rtmr1: `0x${image.rtmr1}` as Hex, rtmr2: `0x${image.rtmr2}` as Hex };
  const imgId = computeImageId("sealed-sim", "1.0.0", measurementsHash(m.mrtd, m.rtmr0, m.rtmr1, m.rtmr2));
  const apps = { crm: computeAppId("crm"), "llm-gateway": computeAppId("llm-gateway") };
  const releases = {
    crm: computeReleaseId(apps.crm, "1.0.0", `0x${"c1".repeat(32)}`),
    "llm-gateway": computeReleaseId(apps["llm-gateway"], "1.0.0", `0x${"11".repeat(32)}`),
  };
  const customerClient = () => {
    const chain = tempoChain({ chainId: node.chainId, rpcUrl: node.rpcUrl, feeToken: PATH_USD });
    return createTempoClient({ chain: chain as never, transport: http(node.rpcUrl), pollingInterval: 100 });
  };
  const root = Account.fromSecp256k1(DEV_KEYS.customer);

  /** Registers a deployment of the crm + llm-gateway stack whose enclave signer comes from `seed`. */
  async function deployment(seed: Hex, salt: Hex) {
    const stackHash = `0x${salt.slice(2, 10).padEnd(64, "a")}` as Hex;
    await approveStack(node, d, DEV_KEYS.customer, { stackHash, releaseIds: [releases.crm, releases["llm-gateway"]], imageId: imgId });
    const deploymentId = computeDeploymentId(CUSTOMER, stackHash, salt);
    const block = await node.client.getBlock();
    await registerDeployment(node, d, {
      deploymentId,
      customer: CUSTOMER,
      stackHash,
      imageId: imgId,
      quoteHash: `0x${salt.slice(2, 4)}${"0a".repeat(31)}`,
      eventLogHash: `0x${"0b".repeat(32)}`,
      configHash: `0x${"0c".repeat(32)}`,
      enclaveSigner: enclaveSignerAddress(seed),
      attestedAt: block.timestamp,
    });
    return deploymentId;
  }

  function harness(mode: "access-key" | "enclave-account", seed: Hex, deploymentId: Hex) {
    const enclaveKey = deriveEnclavePrivateKey(seed);
    const payer = new TempoFeePayer({
      mode,
      enclaveKey,
      customer: CUSTOMER,
      chainId: node.chainId,
      rpcUrl: node.rpcUrl,
      feeToken: PATH_USD,
      feeSplitter: d.feeSplitter,
      deploymentRegistry: d.deploymentRegistry,
      deploymentId,
      receiptTimeoutMs: 10_000,
      minGas: 5_000_000n,
    });
    let cap = 0n;
    const ledger = new Ledger(emptyLedgerState(1000), {
      deploymentId,
      apps: ["crm", "llm-gateway"],
      schedule: feeScheduleFromDefaults(defaults),
      domain: usageDomain(d.feeSplitter, node.chainId),
      enclaveKey,
      perPaymentCap: () => cap,
    });
    const status: PaymentStatus = { failingSince: null, paymentNeeded: false };
    let saved: unknown;
    const gate = new PaymentGate(new SocketCaddyAdmin(parseEndpoint(join(dir, "admin.sock"))), ["crm.34-1-2-3.sslip.io", "gateway.34-1-2-3.sslip.io"], {
      getOriginal: () => saved,
      setOriginal: async (c) => {
        saved = c;
      },
    });
    const usage: unknown[] = [];
    const platform: PlatformClient = { postEvidence: async () => ({ deploymentId }), postUsage: async (b) => void usage.push(b), postHealth: async () => undefined };
    const settler = new Settler({ ledger, payer, platform, gate, status, graceSec: defaults.grace_period_minutes * 60, save: async () => {}, log: testLog });
    return { payer, ledger, status, settler, usage, setCap: (c: bigint) => (cap = c) };
  }

  async function feesPaidEvents(txHash: Hex) {
    const receipt = await node.client.getTransactionReceipt({ hash: txHash });
    return parseEventLogs({ abi: feeSplitterAbi, logs: receipt.logs, eventName: "FeesPaid" });
  }

  const credited = (who: Address) =>
    node.client.readContract({ address: d.feeSplitter, abi: feeSplitterAbi, functionName: "credited", args: [PATH_USD, who] });

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-pay-"));
    caddy = await startFakeCaddy(join(dir, "admin.sock"), sampleCaddyConfig("34-1-2-3"));
    node = await startLocalTempo();
    d = await deploySealedContracts(node, { perPaymentCap: PER_PAYMENT_CAP, perDeploymentDailyCap: DAILY_CAP });
    await addImage(node, d, { imageId: imgId, name: "sealed-sim", version: "1.0.0", ...m });
    await registerApp(node, d, { appId: apps.crm, slug: "crm", shareBps: 5000 });
    await registerApp(node, d, { appId: apps["llm-gateway"], slug: "llm-gateway", shareBps: 2000 });
    await publishRelease(node, d, { appId: apps.crm, version: "1.0.0", bundleHash: `0x${"c1".repeat(32)}` });
    await publishRelease(node, d, { appId: apps["llm-gateway"], version: "1.0.0", bundleHash: `0x${"11".repeat(32)}` });
  }, 180_000);

  afterAll(async () => {
    await node?.stop();
    await caddy?.close();
    await rm(dir, { recursive: true, force: true });
  });

  describe("access-key mode", () => {
    const seed = `0x${"a1".repeat(32)}` as Hex;
    let h: ReturnType<typeof harness>;
    let deploymentId: Hex;
    const keyId = enclaveSignerAddress(seed);

    beforeAll(async () => {
      deploymentId = await deployment(seed, `0x${"01".repeat(32)}`);
      h = harness("access-key", seed, deploymentId);
    });

    it("payments fail before the customer authorizes the enclave key", async () => {
      h.setCap(await h.payer.perPaymentCap());
      await h.ledger.record("crm", "app_hour", 7200n, 1001);
      const r = await h.settler.tick(2000);
      expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "access_key_missing" }]);
    });

    it("the customer authorizes the enclave key through AccountKeychain with a daily pathUSD limit and scopes", async () => {
      const c = customerClient();
      const hash = await c.writeContract({
        account: root,
        address: Addresses.accountKeychain,
        abi: Abis.accountKeychain,
        functionName: "authorizeKey",
        args: [
          keyId,
          0,
          {
            expiry: 2n ** 64n - 1n,
            enforceLimits: true,
            limits: [{ token: PATH_USD, amount: KEY_LIMIT, period: 86_400n }],
            allowAnyCalls: false,
            allowedCalls: [
              { target: PATH_USD, selectorRules: [{ selector: toFunctionSelector("approve(address,uint256)"), recipients: [d.feeSplitter] }] },
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
        feeToken: PATH_USD,
        gas: 5_000_000n,
      } as never);
      expect((await c.waitForTransactionReceipt({ hash, timeout: 10_000 })).status).toBe("success");
      const meta = await c.accessKey.getMetadata({ account: CUSTOMER, accessKey: keyId });
      expect(meta.address.toLowerCase()).toBe(keyId);
      expect(meta.spendPolicy).toBe("limited");
    });

    it("pays each app in one Tempo transaction, approve(exact) + payFees per report, split at the per-payment cap", async () => {
      const before = await tokenBalance(node, PATH_USD, CUSTOMER);
      await h.ledger.record("llm-gateway", "tokens", 7_000_000n, 2001); // 1.4 USD -> 1.0 + 0.4
      const r = await h.settler.tick(3000);
      expect(r.outcome).toBe("settled");
      const paid = r.apps.filter((a) => a.result === "paid") as Extract<(typeof r.apps)[number], { result: "paid" }>[];
      expect(paid.map((a) => [a.app, a.amount, a.reports])).toEqual([
        ["crm", 100_000n, 1],
        ["llm-gateway", 1_400_000n, 2],
      ]);
      const llmEvents = await feesPaidEvents(paid[1]!.txHash);
      expect(llmEvents.map((e) => e.args.amount)).toEqual([1_000_000n, 400_000n]);
      expect(llmEvents.every((e) => e.args.payer.toLowerCase() === CUSTOMER)).toBe(true);
      // Every payment names the EIP-712 digest of a report that was signed and sent to the platform.
      const domain = usageDomain(d.feeSplitter, node.chainId);
      const posted = h.usage.map((u) => usageReportDigest(usageReportFromJson((u as { report: UsageReportJson }).report), domain));
      expect(posted.length).toBe(3);
      expect(llmEvents.every((e) => posted.includes(e.args.usageHash))).toBe(true);
      expect(new Set(llmEvents.map((e) => e.args.usageHash)).size).toBe(2);
      const tx = await node.client.getTransaction({ hash: paid[1]!.txHash });
      expect(tx.from.toLowerCase()).toBe(CUSTOMER);
      // allowance left at zero: approve was exact
      const allowance = await node.client.readContract({ address: PATH_USD, abi: Abis.tip20, functionName: "allowance", args: [CUSTOMER, d.feeSplitter] });
      expect(allowance).toBe(0n);
      const spentWithFees = before - (await tokenBalance(node, PATH_USD, CUSTOMER));
      expect(spentWithFees > 1_500_000n).toBe(true);
      // maintainer share: crm 50% of 0.1, llm-gateway 20% of 1.4
      expect(await credited(devAddress(DEV_KEYS.maintainer))).toBe(50_000n + 280_000n);
      expect(await credited(devAddress(DEV_KEYS.treasury))).toBe(50_000n + 1_120_000n);
      const { remaining } = await customerClient().accessKey.getRemainingLimit({ account: CUSTOMER, accessKey: keyId, token: PATH_USD });
      expect(remaining < KEY_LIMIT - 1_500_000n).toBe(true);
    });

    it("defers payments beyond the FeeSplitter daily cap and pays them the next day", async () => {
      await h.ledger.record("llm-gateway", "tokens", 6_000_000n, 3001); // 1.2 USD -> 1.0 + 0.2; 1.0 left today
      const r1 = await h.settler.tick(4000);
      expect(r1.apps).toEqual([expect.objectContaining({ app: "llm-gateway", result: "paid", amount: 1_000_000n })]);
      const r2 = await h.settler.tick(4100);
      expect(r2.apps).toEqual([{ app: "llm-gateway", result: "deferred", reason: "daily_cap" }]);
      expect(h.status.failingSince).toBeNull();
      await node.increaseTime(86_400);
      const r3 = await h.settler.tick(4200);
      expect(r3.apps).toEqual([expect.objectContaining({ app: "llm-gateway", result: "paid", amount: 200_000n })]);
    });

    it("an exhausted spending limit switches to the payment-needed page after the grace period; raising it recovers", async () => {
      const c = customerClient();
      const setLimit = async (limit: bigint) => {
        const hash = await c.writeContract({
          account: root,
          address: Addresses.accountKeychain,
          abi: Abis.accountKeychain,
          functionName: "updateSpendingLimit",
          args: [keyId, PATH_USD, limit],
          feeToken: PATH_USD,
          gas: 2_000_000n,
        } as never);
        expect((await c.waitForTransactionReceipt({ hash, timeout: 10_000 })).status).toBe("success");
      };
      await setLimit(1000n);
      await h.ledger.record("crm", "app_hour", 3600n, 5001);
      const t0 = 10_000;
      const grace = defaults.grace_period_minutes * 60;
      expect((await h.settler.tick(t0)).apps).toEqual([{ app: "crm", result: "failed", reason: "spend_limit" }]);
      expect(isPaymentNeededConfig(caddy.config)).toBe(false);
      const r2 = await h.settler.tick(t0 + grace);
      expect(r2.paymentNeeded).toBe(true);
      expect(isPaymentNeededConfig(caddy.config)).toBe(true);
      await setLimit(KEY_LIMIT);
      const r3 = await h.settler.tick(t0 + grace + 60);
      expect(r3.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid", amount: 50_000n })]);
      expect(r3.paymentNeeded).toBe(false);
      expect(caddy.config).toEqual(sampleCaddyConfig("34-1-2-3"));
    });

    // Verification finding on the contract review (logic-F1 b / funds-F-02): the customer pays a leg
    // itself with 1 base unit before the agent does. The agent must not count it as paid.
    it("tops up a leg the customer paid short from its own wallet to the report's fee", async () => {
      await h.ledger.record("crm", "app_hour", 3600n, 6001);
      await h.ledger.closePeriod(6002);
      const [entry] = h.ledger.unpaid();
      expect(entry?.fee).toBe(50_000n);
      const c = customerClient();
      const send = async (address: Address, abi: unknown, functionName: string, args: unknown[]) => {
        const hash = await c.writeContract({ account: root, address, abi, functionName, args, feeToken: PATH_USD, gas: 2_000_000n } as never);
        expect((await c.waitForTransactionReceipt({ hash, timeout: 10_000 })).status).toBe("success");
      };
      await send(PATH_USD, Abis.tip20, "approve", [d.feeSplitter, 1n]);
      await send(d.feeSplitter, feeSplitterAbi, "payFees", [deploymentId, entry!.appId, PATH_USD, 1n, entry!.usageHash]);
      const usagePaid = () =>
        node.client.readContract({ address: d.feeSplitter, abi: feeSplitterAbi, functionName: "usagePaid", args: [deploymentId, entry!.usageHash, entry!.appId] });
      expect(await usagePaid()).toBe(1n);
      const maintainerBefore = await credited(devAddress(DEV_KEYS.maintainer));

      const r = await h.settler.tick(6100);
      expect(r.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid", amount: 49_999n, reports: 1 })]);
      expect(await usagePaid()).toBe(50_000n);
      const paid = r.apps[0] as Extract<(typeof r.apps)[number], { result: "paid" }>;
      const events = await feesPaidEvents(paid.txHash);
      expect(events.map((e) => [e.args.usageHash, e.args.amount, e.args.payer.toLowerCase()])).toEqual([[entry!.usageHash, 49_999n, CUSTOMER]]);
      // crm 50%: 0 of the 1-unit payment (rounded down), 24_999 of the top-up
      expect((await credited(devAddress(DEV_KEYS.maintainer))) - maintainerBefore).toBe(24_999n);
      const allowance = await node.client.readContract({ address: PATH_USD, abi: Abis.tip20, functionName: "allowance", args: [CUSTOMER, d.feeSplitter] });
      expect(allowance).toBe(0n);
      expect(h.ledger.unpaid()).toEqual([]);
      expect(h.status.failingSince).toBeNull();
    });
  });

  describe("enclave-account fallback", () => {
    const seed = `0x${"b2".repeat(32)}` as Hex;
    let h: ReturnType<typeof harness>;
    const enclave = enclaveSignerAddress(seed);

    beforeAll(async () => {
      const deploymentId = await deployment(seed, `0x${"02".repeat(32)}`);
      h = harness("enclave-account", seed, deploymentId);
      h.setCap(PER_PAYMENT_CAP);
    });

    it("fails with an empty balance, then pays from the enclave signer's own account once topped up", async () => {
      await h.ledger.record("crm", "app_hour", 3600n, 1001);
      expect((await h.settler.tick(2000)).apps).toEqual([{ app: "crm", result: "failed", reason: "insufficient_balance" }]);
      await fund(node, PATH_USD, enclave, 1_000_000n);
      const r = await h.settler.tick(2100);
      const paid = r.apps[0] as Extract<(typeof r.apps)[number], { result: "paid" }>;
      expect(paid).toMatchObject({ app: "crm", result: "paid", amount: 50_000n });
      const [ev] = await feesPaidEvents(paid.txHash);
      expect(ev?.args.payer.toLowerCase()).toBe(enclave);
      expect(await tokenBalance(node, PATH_USD, enclave) < 950_000n).toBe(true);
    });
  });
});
