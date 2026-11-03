import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { defaultFeeToken, PATH_USD, tempoChain, USDC_E } from "../src/chain.js";
import { loadDefaults } from "../src/defaults.js";

describe("tempo chain helpers", () => {
  it("mainnet keeps id 4217 and the Tempo serializer", () => {
    const c = tempoChain({ rpcUrl: "https://rpc.example" });
    expect(c.id).toBe(4217);
    expect(c.rpcUrls.default.http[0]).toBe("https://rpc.example");
    expect(typeof c.serializers?.transaction).toBe("function");
    // D-035: mainnet falls back to USDC.e, the token config/defaults.yaml names.
    expect((c as unknown as { feeToken: string }).feeToken.toLowerCase()).toBe(USDC_E);
  });
  it("the configured fee token always wins, and the mainnet fallback matches config/defaults.yaml", async () => {
    const d = await loadDefaults(fileURLToPath(new URL("../../../config/defaults.yaml", import.meta.url)), { testOverrides: false });
    expect(d.chain.fee_token.toLowerCase()).toBe(defaultFeeToken(4217));
    expect((tempoChain({ feeToken: PATH_USD }) as unknown as { feeToken: string }).feeToken).toBe(PATH_USD);
    expect(defaultFeeToken(31337)).toBe(PATH_USD);
  });
  it("local chains reuse the Tempo config with another id", () => {
    const c = tempoChain({ chainId: 31337, rpcUrl: "http://127.0.0.1:9" });
    expect(c.id).toBe(31337);
    expect(typeof c.serializers?.transaction).toBe("function");
    expect((c as unknown as { hardfork: string }).hardfork).toBe("t13");
  });
});
