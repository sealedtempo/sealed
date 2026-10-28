// The D-054 access key end to end on a local Tempo node (Foundry 1.8.6, hardfork T12), with the whole agent:
// the customer authorizes the enclave signer exactly as the console does (buildAccessKeyAuthorization, sent as a
// standard transaction to the AccountKeychain precompile), the shared budget follows the onchain limit and
// period, the relay payer's calls (an MPP charge and an escrow session) and the agent's fee settlement (payFees
// and a topUp leg in one batched Tempo transaction) are signed by the access key and metered by the chain, the
// chain refuses spending over the limit and calls outside the scopes, and revocation stops the key.
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type Address,
  appId as computeAppId,
  buildAccessKeyAuthorization,
  buildAccessKeyRevocation,
  buildSpendingLimitUpdate,
  feeSplitterAbi,
  type Hex,
  imageId as computeImageId,
  loadDefaults,
  measurementsHash,
  releaseId as computeReleaseId,
  sameAllowedCalls,
  SIM_MEASUREMENTS,
  TIP1034_ESCROW,
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
  tokenBalance,
} from "@sealed/core/testing";
import { createWalletClient, defineChain, encodeFunctionData, http, keccak256, parseEventLogs, toFunctionSelector } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Abis, Account, Addresses, createClient } from "viem/tempo";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent } from "../src/agent.js";
import { DstackClient } from "../src/dstack.js";
import { localRequest, parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import { fixedTlsKey } from "../src/tls.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { type FakePlatform, startFakePlatform } from "./helpers/fakePlatform.js";
import { CADDYFILE, fromPeer, IPS, makeAppCompose, makeConfig, testPeerOf, testSettings } from "./helpers/fixtures.js";

const enabled = chainTestsEnabled();
const PATH_USD = LOCAL_TOKENS.pathUsd;
const WEEK = 604_800;
/** The customer's choice in the console: 12 USD a week (the config still says 2 USD a day). */
const LIMIT = 12_000_000n;
/** AccountKeychain errors the node reports, by name (custom errors show as selectors in an estimate's revert). */
const tempoClient = (chainId: number, rpcUrl: string) =>
  createClient({ chain: tempoChain({ chainId, rpcUrl, feeToken: PATH_USD }) as never, transport: http(rpcUrl), pollingInterval: 100 });
const KEYCHAIN_ERRORS = ["SpendingLimitExceeded", "CallNotAllowed", "KeyNotFound", "KeyAlreadyRevoked", "KeyExpired"];

describe.skipIf(!enabled)("the D-054 access key end to end on a local Tempo node (T12)", () => {
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
  const treasury = devAddress(DEV_KEYS.treasury);
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

  let keyId: Address;
  let auth: ReturnType<typeof buildAccessKeyAuthorization>;
  let periodEnd: number;
  /** The customer's root account through a Tempo client (reads, and the root's own Tempo transactions). */
  let tempo: ReturnType<typeof tempoClient>;
  /** The enclave signer as an access key of the customer: what sealed-mpp-payer and the fee payer sign with. */
  let accessKey: ReturnType<typeof Account.fromSecp256k1>;

  const ep = () => parseEndpoint(`http://127.0.0.1:${agent.port}`);
  const asPayer = (path: string, body: unknown) => localRequest(ep(), path, { body, headers: fromPeer(IPS.payer) });
  const remaining = async () => (await tempo.accessKey.getRemainingLimit({ account: customer, accessKey: keyId, token: PATH_USD })).remaining;
  /** The customer's injected wallet: standard (type 2) transactions only, no Tempo envelope (D-026). */
  const injected = () => {
    const chain = defineChain({ id: node.chainId, name: "Tempo local", nativeCurrency: { name: "USD", symbol: "USD", decimals: 6 }, rpcUrls: { default: { http: [node.rpcUrl] } } });
    return createWalletClient({ chain, transport: http(node.rpcUrl), account: privateKeyToAccount(customerKey) });
  };
  const sendInjected = async (call: { to: Address; data: Hex }) => {
    const hash = await injected().sendTransaction({ to: call.to, data: call.data, type: "eip1559" });
    const receipt = await node.client.waitForTransactionReceipt({ hash, timeout: 10_000 });
    return { hash, receipt, tx: await node.client.getTransaction({ hash }) };
  };
  /** The keychain error the node reports for a batch signed by the access key (from its gas estimate). */
  const refusal = async (calls: { to: Address; data: Hex }[]) => {
    try {
      await tempo.estimateGas({ account: accessKey, calls, feeToken: PATH_USD } as never);
      return "accepted";
    } catch (err) {
      const msg = String((err as Error).message);
      const named = KEYCHAIN_ERRORS.find((e) => msg.includes(e) || msg.includes(toFunctionSelector(`${e}()`)));
      return named ?? msg;
    }
  };
  /** A Tempo transaction signed by the access key, as sealed-mpp-payer sends one. */
  const sendAsKey = async (calls: { to: Address; data: Hex }[], o: { expiring?: boolean; gas?: bigint } = {}) => {
    const hash = await tempo.sendTransaction({
      account: accessKey,
      calls,
      feeToken: PATH_USD,
      gas: o.gas ?? 3_000_000n,
      ...(o.expiring ? { nonceKey: "expiring" } : {}),
    } as never);
    return tempo.waitForTransactionReceipt({ hash, timeout: 10_000 });
  };
  const usagePaid = (deploymentId: Hex, usageHash: Hex) =>
    node.client.readContract({ address: d.feeSplitter, abi: feeSplitterAbi, functionName: "usagePaid", args: [deploymentId, usageHash, crm] });
  const allowance = () => node.client.readContract({ address: PATH_USD, abi: Abis.tip20, functionName: "allowance", args: [customer, d.feeSplitter] });

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-access-key-"));
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
      feeToken: PATH_USD,
      settlement: { mode: "access-key", intervalMinutes: 60, gracePeriodMinutes: 1440, spendLimitPerDay: "2000000" },
    });
    await writeFile(join(dir, "config.json"), JSON.stringify(config));
    sim = await startSimulator({ appCompose: makeAppCompose(config), socket: join(dir, "dstack.sock") });
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
    keyId = agent.enclaveSigner as Address;
    tempo = tempoClient(node.chainId, node.rpcUrl);
    accessKey = Account.fromSecp256k1(agent.keys?.enclaveKey as Hex, { access: customer });

    // The oracle registers the deployment from the agent's evidence, after the customer approved the stack.
    const b = platform.evidence[0];
    if (!b) throw new Error("no evidence");
    await approveStack(node, d, customerKey, { stackHash: b.stackHash as Hex, releaseIds: b.releaseIds as Hex[], imageId });
    const block = await node.client.getBlock();
    await registerDeployment(node, d, {
      deploymentId: b.deploymentId as Hex,
      customer,
      stackHash: b.stackHash as Hex,
      imageId,
      quoteHash: b.quoteHash as Hex,
      eventLogHash: b.eventLogHash as Hex,
      configHash: b.configHash as Hex,
      enclaveSigner: keyId,
      attestedAt: block.timestamp,
    });
  }, 180_000);

  afterAll(async () => {
    await agent?.stop();
    await Promise.all([broker?.close(), platform?.close(), caddy?.close(), sim?.close()]);
    await node?.stop();
    await rm(dir, { recursive: true, force: true });
  });

  it("before the customer authorizes the key, the payer gets nothing (no config fallback)", async () => {
    const r = await asPayer("/v1/spend/reserve", { amount: "1000", currency: PATH_USD });
    expect(JSON.parse(r.body)).toEqual({ ok: false, remaining: "0", reason: "budget" });
    expect(agent.budget?.state.onchain).toMatchObject({ remaining: "0" });
  });

  it("the customer authorizes the enclave key exactly with buildAccessKeyAuthorization, from an injected wallet", async () => {
    auth = buildAccessKeyAuthorization({ keyId, feeToken: PATH_USD, feeSplitter: d.feeSplitter, treasury, limit: LIMIT, period: "week" });
    const { receipt, tx } = await sendInjected(auth.call);
    expect(receipt.status).toBe("success");
    expect(tx.type).toBe("eip1559");
    expect(tx.to?.toLowerCase()).toBe(Addresses.accountKeychain.toLowerCase());
    // What the chain holds is exactly the helper's list: no call more, no recipient less.
    const [isScoped, scopes] = await node.client.readContract({ address: Addresses.accountKeychain, abi: Abis.accountKeychain, functionName: "getAllowedCalls", args: [customer, keyId] });
    expect(isScoped).toBe(true);
    expect(sameAllowedCalls(auth, scopes)).toBe(true);
    expect(scopes.flatMap((s) => s.selectorRules).length).toBe(8);
    const meta = await tempo.accessKey.getMetadata({ account: customer, accessKey: keyId });
    expect(meta).toMatchObject({ spendPolicy: "limited", isRevoked: false, expiry: 2n ** 64n - 1n });
    const limit = await tempo.accessKey.getRemainingLimit({ account: customer, accessKey: keyId, token: PATH_USD });
    const block = await node.client.getBlock({ blockNumber: receipt.blockNumber });
    expect(limit).toMatchObject({ remaining: LIMIT, periodEnd: block.timestamp + BigInt(WEEK) });
    periodEnd = Number(limit.periodEnd);
    // Recipient rules on the escrow selectors are refused by the keychain, so the helper cannot bind the payee there.
    const widened = buildAccessKeyAuthorization({ keyId: devAddress(`0x${"5d".repeat(32)}` as Hex), feeToken: PATH_USD, feeSplitter: d.feeSplitter, treasury, limit: LIMIT, period: "week" });
    const cfg = { ...widened.config, allowedCalls: widened.config.allowedCalls.map((c) => (c.target === TIP1034_ESCROW ? { ...c, selectorRules: c.selectorRules.map((r) => ({ ...r, recipients: [treasury] })) } : c)) };
    await expect(
      node.client.simulateContract({ account: privateKeyToAccount(customerKey), address: Addresses.accountKeychain, abi: Abis.accountKeychain, functionName: "authorizeKey", args: [widened.keyId, 0, cfg] }),
    ).rejects.toThrow("InvalidCallScope");
  });

  it("the shared budget follows the onchain limit and period, and fee settlement keeps the week's app-hours", async () => {
    await agent.settle();
    const now = clock.now();
    const snap = agent.budget?.snapshot(now) ?? {};
    expect(snap).toMatchObject({ budget_source: "onchain", budget_onchainRemaining: LIMIT.toString(), budget_windowEnd: String(periodEnd) });
    // crm costs 0.05 USD an hour: most of the 12 USD stays reserved for the week's fees (8.40 USD and network fees).
    const reserved = agent.feeReserve(periodEnd, now);
    expect(reserved > 8_350_000n).toBe(true);
    expect(agent.budget?.available(now)).toBe(LIMIT - reserved);
  });

  it("the relay payer's MPP charge and escrow session are signed by the access key and count against its limit", async () => {
    const before = await remaining();
    const res = JSON.parse((await asPayer("/v1/spend/reserve", { amount: "600000", currency: PATH_USD })).body);
    expect(res).toMatchObject({ ok: true });
    // Charge: transferWithMemo to the treasury (the attested payee).
    const treasuryBefore = await tokenBalance(node, PATH_USD, treasury);
    const charge = await sendAsKey([{ to: PATH_USD, data: encodeFunctionData({ abi: Abis.tip20, functionName: "transferWithMemo", args: [treasury, 50_000n, `0x${"ab".repeat(32)}`] }) }]);
    expect(charge.status).toBe("success");
    expect((await tokenBalance(node, PATH_USD, treasury)) - treasuryBefore).toBe(50_000n);
    // Session: open a 0.4 USD channel to the treasury, then top it up by 0.1 USD; the deposits are pulled from
    // the customer and metered by the key's limit.
    const salt = `0x${"0e".repeat(32)}` as Hex;
    const open = await sendAsKey(
      [{ to: TIP1034_ESCROW, data: encodeFunctionData({ abi: Abis.tip20ChannelReserve, functionName: "open", args: [treasury, "0x0000000000000000000000000000000000000000", PATH_USD, 400_000n, salt, keyId] }) }],
      { expiring: true },
    );
    expect(open.status).toBe("success");
    const [opened] = parseEventLogs({ abi: Abis.tip20ChannelReserve, logs: open.logs, eventName: "ChannelOpened" });
    expect(opened?.args).toMatchObject({ payee: expect.stringMatching(new RegExp(treasury.slice(2), "i")), deposit: 400_000n });
    const a = opened?.args as { payer: Address; payee: Address; operator: Address; token: Address; salt: Hex; authorizedSigner: Address; expiringNonceHash: Hex };
    const descriptor = { payer: a.payer, payee: a.payee, operator: a.operator, token: a.token, salt: a.salt, authorizedSigner: a.authorizedSigner, expiringNonceHash: a.expiringNonceHash };
    const escrowCall = (functionName: "topUp" | "requestClose" | "withdraw", extra: unknown[] = []) => ({
      to: TIP1034_ESCROW,
      data: encodeFunctionData({ abi: Abis.tip20ChannelReserve, functionName, args: [descriptor, ...extra] as never }),
    });
    expect((await sendAsKey([escrowCall("topUp", [100_000n])])).status).toBe("success");
    const spent = before - (await remaining());
    // 0.55 USD moved plus the three transactions' network fees, all against the limit.
    expect(spent > 550_000n && spent < 600_000n).toBe(true);
    const rel = JSON.parse((await asPayer("/v1/spend/release", { reservationId: res.reservationId, used: spent.toString() })).body);
    expect(rel.ok).toBe(true);
    // After a fresh read the agent's view and the chain agree: remaining less reserved_for_fees.
    await agent.settle();
    expect(agent.budget?.state.onchain?.remaining).toBe((await remaining()).toString());
    expect(agent.budget?.available(clock.now())).toBe((await remaining()) - agent.feeReserve(periodEnd, clock.now()));
    // Close the session: the payer asks to close, and withdraws the unspent deposit after the grace period.
    expect((await sendAsKey([escrowCall("requestClose")])).status).toBe("success");
    await node.increaseTime(901);
    const balanceBefore = await tokenBalance(node, PATH_USD, customer);
    expect((await sendAsKey([escrowCall("withdraw")])).status).toBe("success");
    expect((await tokenBalance(node, PATH_USD, customer)) - balanceBefore > 490_000n).toBe(true);
  });

  let deploymentId: Hex;
  it("the agent settles payFees and a topUp leg in one batched Tempo transaction signed by the access key", async () => {
    deploymentId = agent.ctx?.deploymentId as Hex;
    const ledger = agent.ledger;
    if (!ledger) throw new Error("no ledger");
    const t = clock.now();
    // Leg A: one hour of crm, which the customer pays short (1 unit) from its own wallet before the agent does.
    await ledger.record("crm", "app_hour", 3600n, t);
    await ledger.closePeriod(t + 1);
    const legA = ledger.unpaid().find((e) => e.app === "crm");
    if (!legA) throw new Error("no crm leg");
    const root = Account.fromSecp256k1(customerKey);
    const rootCalls = [
      { to: PATH_USD, data: encodeFunctionData({ abi: Abis.tip20, functionName: "approve", args: [d.feeSplitter, 1n] }) },
      { to: d.feeSplitter, data: encodeFunctionData({ abi: feeSplitterAbi, functionName: "payFees", args: [deploymentId, crm, PATH_USD, 1n, legA.usageHash] }) },
    ];
    const rootPaid = await tempo.waitForTransactionReceipt({ hash: await tempo.sendTransaction({ account: root, calls: rootCalls, feeToken: PATH_USD, gas: 3_000_000n } as never) });
    expect(rootPaid.status).toBe("success");
    expect(await usagePaid(deploymentId, legA.usageHash)).toBe(1n);
    // Leg B: another hour, cut by the settlement itself.
    await ledger.record("crm", "app_hour", 3600n, t + 2);
    const limitBefore = await remaining();
    const feesBefore = BigInt(agent.budget?.state.fees ?? "0");
    const result = await agent.settle(t + 3);
    expect(result.outcome).toBe("settled");
    const paid = result.apps.find((a) => a.app === "crm") as Extract<(typeof result.apps)[number], { result: "paid" }>;
    expect(paid).toMatchObject({ result: "paid", amount: 49_999n + 50_000n, reports: 2 });
    const legB = ledger.state.reports.at(-1)?.usageHash as Hex;
    expect(await usagePaid(deploymentId, legA.usageHash)).toBe(50_000n);
    expect(await usagePaid(deploymentId, legB)).toBe(50_000n);

    // One Tempo (0x76) transaction from the customer, signed by the enclave signer's access key, with the calls
    // approve(exact), topUpFees, payFees, approve(0).
    const tx = await tempo.getTransaction({ hash: paid.txHash });
    expect(tx.type).toBe("tempo");
    // The hash TempoFeePayer computes before sending (keccak256 of the signed bytes) is the node's hash, so a
    // payment whose answer is lost can still be found and counted.
    const raw = (await node.client.request({ method: "eth_getRawTransactionByHash" as never, params: [paid.txHash] as never })) as Hex;
    expect(keccak256(raw)).toBe(paid.txHash);
    expect(tx.from.toLowerCase()).toBe(customer);
    const sig = (tx as unknown as { signature: { type: string; userAddress?: string } }).signature;
    expect(sig.type).toBe("keychain");
    expect(sig.userAddress?.toLowerCase()).toBe(customer);
    const calls = (tx as unknown as { calls: { to: string; data?: Hex; input?: Hex }[] }).calls;
    expect(calls.map((c) => (c.data ?? c.input ?? "0x").slice(0, 10))).toEqual([
      toFunctionSelector("approve(address,uint256)"),
      auth.calls.find((c) => c.name === "feeSplitter.topUpFees")?.selector,
      auth.calls.find((c) => c.name === "feeSplitter.payFees")?.selector,
      toFunctionSelector("approve(address,uint256)"),
    ]);
    const receipt = await node.client.getTransactionReceipt({ hash: paid.txHash });
    const events = parseEventLogs({ abi: feeSplitterAbi, logs: receipt.logs, eventName: "FeesPaid" });
    expect(events.map((e) => [e.args.usageHash, e.args.amount, e.args.payer.toLowerCase()])).toEqual([
      [legA.usageHash, 49_999n, customer],
      [legB, 50_000n, customer],
    ]);
    expect(await allowance()).toBe(0n);
    // The budget counted exactly what left the key's limit: the approved fees plus the network fee.
    const limitSpent = limitBefore - (await remaining());
    expect(BigInt(agent.budget?.state.fees ?? "0") - feesBefore).toBe(limitSpent);
    expect(limitSpent > 99_999n).toBe(true);
  });

  it("the chain refuses spending over the limit and calls outside the scopes", async () => {
    // The customer lowers the limit (an existing key: updateSpendingLimit from the helper, the period stays).
    expect((await sendInjected(buildSpendingLimitUpdate({ keyId, feeToken: PATH_USD, limit: 40_000n }))).receipt.status).toBe("success");
    expect(await remaining()).toBe(40_000n);
    const ledger = agent.ledger;
    if (!ledger) throw new Error("no ledger");
    const t = clock.now();
    await ledger.record("crm", "app_hour", 3600n, t);
    await ledger.closePeriod(t + 1);
    const leg = ledger.unpaid().find((e) => e.app === "crm");
    if (!leg) throw new Error("no crm leg");
    // The agent sees it cannot pay and does not try.
    const r = await agent.settle(t + 2);
    expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "spend_limit" }]);
    // The same batch sent anyway (explicit gas, no estimate) is refused by the chain: nothing is pulled.
    const batch = [
      { to: PATH_USD, data: encodeFunctionData({ abi: Abis.tip20, functionName: "approve", args: [d.feeSplitter, leg.fee] }) },
      { to: d.feeSplitter, data: encodeFunctionData({ abi: feeSplitterAbi, functionName: "payFees", args: [deploymentId, crm, PATH_USD, leg.fee, leg.usageHash] }) },
    ];
    expect(await refusal(batch)).toBe("SpendingLimitExceeded");
    expect((await sendAsKey(batch, { gas: 5_000_000n })).status).toBe("reverted");
    expect(await usagePaid(deploymentId, leg.usageHash)).toBe(0n);
    expect(await allowance()).toBe(0n);
    // An MPP charge above what is left is refused too.
    const charge = (to: Address, amount: bigint) => ({ to: PATH_USD, data: encodeFunctionData({ abi: Abis.tip20, functionName: "transferWithMemo", args: [to, amount, `0x${"cd".repeat(32)}`] }) });
    expect(await refusal([charge(treasury, 100_000n)])).toBe("SpendingLimitExceeded");
    expect((await sendAsKey([charge(treasury, 100_000n)])).status).toBe("reverted");
    // Raise it again: within the limit, but outside the scopes, the chain refuses as well.
    expect((await sendInjected(buildSpendingLimitUpdate({ keyId, feeToken: PATH_USD, limit: LIMIT }))).receipt.status).toBe("success");
    const maintainer = devAddress(DEV_KEYS.maintainer);
    const before = await tokenBalance(node, PATH_USD, maintainer);
    const outside = [
      charge(maintainer, 1_000n), // transferWithMemo to anyone but the treasury
      { to: PATH_USD, data: encodeFunctionData({ abi: Abis.tip20, functionName: "transfer", args: [treasury, 1_000n] }) }, // plain transfer
      { to: PATH_USD, data: encodeFunctionData({ abi: Abis.tip20, functionName: "approve", args: [maintainer, 1_000n] }) }, // approve to anyone but FeeSplitter
      { to: d.feeSplitter, data: encodeFunctionData({ abi: feeSplitterAbi, functionName: "withdraw", args: [PATH_USD] }) }, // another FeeSplitter function
    ];
    for (const call of outside) {
      expect(await refusal([call])).toBe("CallNotAllowed");
      expect((await sendAsKey([call])).status).toBe("reverted");
    }
    expect(await tokenBalance(node, PATH_USD, maintainer)).toBe(before);
    // And the agent pays the leg once the limit allows it.
    const paid = await agent.settle(t + 3);
    expect(paid.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid", amount: leg.fee })]);
  });

  it("revoking the key with buildAccessKeyRevocation stops the payer and fee settlement", async () => {
    const rev = buildAccessKeyRevocation({ keyId, feeToken: PATH_USD, feeSplitter: d.feeSplitter });
    for (const call of rev.calls) expect((await sendInjected(call)).receipt.status).toBe("success");
    const meta = await tempo.accessKey.getMetadata({ account: customer, accessKey: keyId });
    expect(meta.isRevoked).toBe(true);
    expect(await allowance()).toBe(0n);
    // The node no longer accepts transactions signed by the key.
    await expect(sendAsKey([{ to: PATH_USD, data: encodeFunctionData({ abi: Abis.tip20, functionName: "transferWithMemo", args: [treasury, 1n, `0x${"ef".repeat(32)}`] }) }])).rejects.toThrow();
    // The agent reports the revocation, and the shared budget gives the payer nothing.
    const ledger = agent.ledger;
    if (!ledger) throw new Error("no ledger");
    const t = clock.now();
    await ledger.record("crm", "app_hour", 3600n, t);
    const r = await agent.settle(t + 1);
    expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "access_key_revoked" }]);
    expect(agent.budget?.state.onchain).toMatchObject({ remaining: "0" });
    expect(JSON.parse((await asPayer("/v1/spend/reserve", { amount: "1", currency: PATH_USD })).body)).toMatchObject({ ok: false, remaining: "0" });
  });
});
