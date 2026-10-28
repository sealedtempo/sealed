// The D-054 access-key authorization helper: exact limits and allowed calls, selectors checked against their
// signatures and the ABIs they call, the revoke and limit-update calls, and the onchain comparison.
import { decodeFunctionData, getAbiItem, maxUint64, toFunctionSelector } from "viem";
import { Abis } from "viem/tempo";
import { describe, expect, it } from "vitest";
import {
  ACCESS_KEY_SELECTORS,
  appHourFeeFloor,
  buildAccessKeyAuthorization,
  buildAccessKeyRevocation,
  buildSpendingLimitUpdate,
  MAINNET_TREASURY,
  sameAllowedCalls,
  SPEND_PERIOD_SECONDS,
  TIP1034_ESCROW,
} from "../src/accessKey.js";
import { feeSplitterAbi } from "../src/abis/index.js";
import { ACCOUNT_KEYCHAIN, USDC_E } from "../src/chain.js";

const KEY = "0x976EA74026E726554dB657fA54763abd0C3a0aa9";
const FEE_SPLITTER = "0x3D288c0756c3F26Da0f41257D688bAB3dB3d94AD";
const params = { keyId: KEY, feeToken: USDC_E, feeSplitter: FEE_SPLITTER, treasury: MAINNET_TREASURY, limit: 2_000_000n, period: "day" } as const;

describe("buildAccessKeyAuthorization (D-054)", () => {
  it("selectors are the signatures' and exist in the ABIs the key calls", () => {
    const s = ACCESS_KEY_SELECTORS;
    const desc = "(address,address,address,address,bytes32,address,bytes32)";
    expect(s).toEqual({
      approve: toFunctionSelector("approve(address,uint256)"),
      transferWithMemo: toFunctionSelector("transferWithMemo(address,uint256,bytes32)"),
      payFees: toFunctionSelector("payFees(bytes32,bytes32,address,uint256,bytes32)"),
      topUpFees: toFunctionSelector("topUpFees(bytes32,bytes32,address,uint256,bytes32)"),
      escrowOpen: toFunctionSelector("open(address,address,address,uint96,bytes32,address)"),
      escrowTopUp: toFunctionSelector(`topUp(${desc},uint96)`),
      escrowRequestClose: toFunctionSelector(`requestClose(${desc})`),
      escrowWithdraw: toFunctionSelector(`withdraw(${desc})`),
    });
    const sel = (abi: readonly unknown[], name: string) => toFunctionSelector(getAbiItem({ abi: abi as never, name: name as never }) as never);
    expect(sel(Abis.tip20, "approve")).toBe(s.approve);
    expect(sel(Abis.tip20, "transferWithMemo")).toBe(s.transferWithMemo);
    expect(sel(feeSplitterAbi, "payFees")).toBe(s.payFees);
    expect(sel(feeSplitterAbi, "topUpFees")).toBe(s.topUpFees);
    expect(sel(Abis.tip20ChannelReserve, "open")).toBe(s.escrowOpen);
    expect(sel(Abis.tip20ChannelReserve, "topUp")).toBe(s.escrowTopUp);
    expect(sel(Abis.tip20ChannelReserve, "requestClose")).toBe(s.escrowRequestClose);
    expect(sel(Abis.tip20ChannelReserve, "withdraw")).toBe(s.escrowWithdraw);
  });

  it("allows exactly the fee and relay calls, with one periodic limit in the fee token", () => {
    const a = buildAccessKeyAuthorization(params);
    const fs = FEE_SPLITTER.toLowerCase();
    expect(a.keyId).toBe(KEY.toLowerCase());
    expect(a.config).toEqual({
      expiry: maxUint64,
      enforceLimits: true,
      limits: [{ token: USDC_E, amount: 2_000_000n, period: 86_400n }],
      allowAnyCalls: false,
      allowedCalls: [
        {
          target: USDC_E,
          selectorRules: [
            { selector: "0x095ea7b3", recipients: [fs] },
            { selector: "0x95777d59", recipients: [MAINNET_TREASURY] },
          ],
        },
        { target: fs, selectorRules: [{ selector: "0xa1e03ecd", recipients: [] }, { selector: "0x01571ecd", recipients: [] }] },
        {
          target: TIP1034_ESCROW,
          selectorRules: ["0xedc53b00", "0xdc48471e", "0x675402e5", "0x41e2c664"].map((selector) => ({ selector, recipients: [] })),
        },
      ],
    });
    expect(a.calls.map((c) => c.name)).toEqual([
      "feeToken.approve",
      "feeToken.transferWithMemo",
      "feeSplitter.payFees",
      "feeSplitter.topUpFees",
      "escrow.open",
      "escrow.topUp",
      "escrow.requestClose",
      "escrow.withdraw",
    ]);
    // The transaction an injected wallet sends decodes back to the same authorizeKey call.
    expect(a.call.to).toBe(ACCOUNT_KEYCHAIN);
    const d = decodeFunctionData({ abi: Abis.accountKeychain, data: a.call.data });
    expect(d.functionName).toBe("authorizeKey");
    expect(a.call.data.slice(0, 10)).toBe("0x980a6025");
    const [keyId, sigType, cfg] = d.args as unknown as [string, number, { expiry: bigint; enforceLimits: boolean; limits: { token: string; amount: bigint; period: bigint }[]; allowAnyCalls: boolean; allowedCalls: never }];
    expect([keyId, sigType]).toEqual([KEY, 0]);
    expect({ ...cfg, allowedCalls: undefined, limits: cfg.limits.map((l) => ({ ...l, token: l.token.toLowerCase() })) }).toEqual({ ...a.config, allowedCalls: undefined });
    expect(sameAllowedCalls(a, cfg.allowedCalls)).toBe(true);
    expect(a.args).toEqual([a.keyId, 0, a.config]);
  });

  it("takes the customer's period and expiry", () => {
    expect(buildAccessKeyAuthorization({ ...params, period: "week" }).config.limits[0]?.period).toBe(BigInt(SPEND_PERIOD_SECONDS.week));
    expect(buildAccessKeyAuthorization({ ...params, period: "month" }).config.limits[0]?.period).toBe(2_592_000n);
    expect(buildAccessKeyAuthorization({ ...params, period: 3600 }).config.limits[0]?.period).toBe(3600n);
    expect(buildAccessKeyAuthorization({ ...params, expiry: 1_900_000_000n }).config.expiry).toBe(1_900_000_000n);
  });

  it("refuses inputs that would widen or break the authorization", () => {
    expect(() => buildAccessKeyAuthorization({ ...params, limit: 0n })).toThrow("limit");
    expect(() => buildAccessKeyAuthorization({ ...params, limit: 1n << 128n })).toThrow("limit");
    expect(() => buildAccessKeyAuthorization({ ...params, period: 0 })).toThrow("period");
    expect(() => buildAccessKeyAuthorization({ ...params, period: "year" as never })).toThrow("period");
    expect(() => buildAccessKeyAuthorization({ ...params, expiry: 0n })).toThrow("expiry");
    expect(() => buildAccessKeyAuthorization({ ...params, treasury: "0x0000000000000000000000000000000000000000" })).toThrow("treasury");
    expect(() => buildAccessKeyAuthorization({ ...params, treasury: FEE_SPLITTER })).toThrow("differ");
    expect(() => buildAccessKeyAuthorization({ ...params, feeSplitter: "0x1234" as never })).toThrow("feeSplitter");
  });
});

describe("revoke, limit update and onchain comparison", () => {
  it("revokes the key and resets the FeeSplitter allowance", () => {
    const r = buildAccessKeyRevocation({ keyId: KEY, feeToken: USDC_E, feeSplitter: FEE_SPLITTER });
    expect(r.calls).toEqual([r.revokeKey, r.resetAllowance]);
    expect(r.revokeKey.to).toBe(ACCOUNT_KEYCHAIN);
    expect(decodeFunctionData({ abi: Abis.accountKeychain, data: r.revokeKey.data })).toEqual({ functionName: "revokeKey", args: [KEY] });
    expect(r.resetAllowance.to).toBe(USDC_E);
    expect(decodeFunctionData({ abi: Abis.tip20, data: r.resetAllowance.data })).toEqual({ functionName: "approve", args: [FEE_SPLITTER, 0n] });
  });

  it("updates the limit of an existing key", () => {
    const u = buildSpendingLimitUpdate({ keyId: KEY, feeToken: USDC_E, limit: 5_000_000n });
    expect(u.to).toBe(ACCOUNT_KEYCHAIN);
    expect(decodeFunctionData({ abi: Abis.accountKeychain, data: u.data })).toEqual({
      functionName: "updateSpendingLimit",
      args: [KEY, "0x20C000000000000000000000b9537d11c60E8b50", 5_000_000n],
    });
  });

  it("compares allowed calls ignoring order and case, and catches any extra, missing or widened call", () => {
    const a = buildAccessKeyAuthorization(params);
    const onchain = [...a.config.allowedCalls]
      .reverse()
      .map((c) => ({ target: c.target.toUpperCase().replace("0X", "0x"), selectorRules: [...c.selectorRules].reverse() }));
    expect(sameAllowedCalls(a, onchain)).toBe(true);
    const widened = a.config.allowedCalls.map((c) => ({ ...c, selectorRules: c.selectorRules.map((r) => ({ ...r, recipients: [] })) }));
    expect(sameAllowedCalls(a, widened)).toBe(false);
    expect(sameAllowedCalls(a, a.config.allowedCalls.slice(1))).toBe(false);
    const extra = [...a.config.allowedCalls, { target: USDC_E, selectorRules: [{ selector: "0xa9059cbb" as const, recipients: [] }] }];
    expect(sameAllowedCalls(a, extra)).toBe(false);
  });

  it("app-hour fee floor per period", () => {
    const prices = { crm: 50_000n, "coding-agent": 50_000n, "internal-tools": 50_000n, "llm-gateway": 0n };
    expect(appHourFeeFloor(prices, ["crm", "coding-agent", "internal-tools", "llm-gateway"], "day")).toBe(3_600_000n);
    expect(appHourFeeFloor(prices, ["crm"], "week")).toBe(8_400_000n);
    expect(appHourFeeFloor(prices, ["scraper"], "day")).toBe(0n);
  });
});
