import { describe, expect, it } from "vitest";
import { tempoChain } from "../src/chain.js";

describe("tempo chain helpers", () => {
  it("mainnet keeps id 4217 and the Tempo serializer", () => {
    const c = tempoChain({ rpcUrl: "https://rpc.example" });
    expect(c.id).toBe(4217);
    expect(c.rpcUrls.default.http[0]).toBe("https://rpc.example");
    expect(typeof c.serializers?.transaction).toBe("function");
    expect((c as unknown as { feeToken: string }).feeToken.toLowerCase()).toBe("0x20c0000000000000000000000000000000000000");
  });
  it("local chains reuse the Tempo config with another id", () => {
    const c = tempoChain({ chainId: 31337, rpcUrl: "http://127.0.0.1:9" });
    expect(c.id).toBe(31337);
    expect(typeof c.serializers?.transaction).toBe("function");
    expect((c as unknown as { hardfork: string }).hardfork).toBe("t4");
  });
});
