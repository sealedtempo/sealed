import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bytesToBareHex, decodeSimQuote, replayRtmr3, sha256Hex, SIM_DEBUG_MRTD, verifySealedEventLog } from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { padReportData, startSimulator } from "../sim/simulator.js";
import { DstackClient } from "../src/dstack.js";
import { parseEndpoint, localRequest } from "../src/http.js";
import { makeAppCompose, makeConfig } from "./helpers/fixtures.js";

describe("dstack simulator", () => {
  let dir: string;
  let composePath: string;
  const compose = makeAppCompose(makeConfig());
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-sim-"));
    composePath = join(dir, "app-compose.json");
    await writeFile(composePath, compose);
  });
  afterAll(async () => rm(dir, { recursive: true, force: true }));

  for (const transport of ["socket", "tcp"] as const) {
    it(`serves GetQuote and Info over ${transport}`, async () => {
      const sim = await startSimulator(transport === "socket" ? { appComposePath: composePath, socket: join(dir, "dstack.sock") } : { appComposePath: composePath, port: 0 });
      try {
        const client = new DstackClient(parseEndpoint(sim.endpoint));
        expect(await client.appCompose()).toBe(compose);
        const rd = new Uint8Array(64).fill(7);
        const q = await client.getQuote(rd);
        const decoded = decodeSimQuote(q.quote);
        expect(decoded.reportData).toBe(bytesToBareHex(rd));
        expect(decoded.mrtd).toBe("11".repeat(48));
        expect(decoded.debug).toBe(false);
        expect(decoded.rtmr3).toBe(bytesToBareHex(replayRtmr3(q.eventLog)));
        expect(bytesToBareHex(verifySealedEventLog(q.eventLog, compose))).toBe(decoded.rtmr3);
        expect(q.eventLog[2]?.event_payload).toBe(sha256Hex(compose).slice(2));
      } finally {
        await sim.close();
      }
    });
  }

  it("pads short report_data, rejects more than 64 bytes and unknown methods", async () => {
    expect(padReportData("abcd")).toEqual(Uint8Array.from([0xab, 0xcd, ...new Array(62).fill(0)]));
    const sim = await startSimulator({ appComposePath: composePath, port: 0 });
    try {
      const ep = parseEndpoint(sim.endpoint);
      const short = await localRequest(ep, "/GetQuote", { body: { report_data: "0xabcd" } });
      expect(JSON.parse(short.body).report_data).toBe(`abcd${"00".repeat(62)}`);
      const long = await localRequest(ep, "/GetQuote", { body: { report_data: "00".repeat(65) } });
      expect(long.status).toBe(400);
      expect(JSON.parse(long.body).error).toMatch(/64 bytes/);
      expect((await localRequest(ep, "/v0/Version")).status).toBe(200);
      expect((await localRequest(ep, "/GetKey", { body: {} })).status).toBe(404);
    } finally {
      await sim.close();
    }
  });

  it("debug mode uses the debug measurements", async () => {
    const sim = await startSimulator({ appCompose: compose, port: 0, debug: true });
    try {
      const q = await new DstackClient(parseEndpoint(sim.endpoint)).getQuote(new Uint8Array(64));
      const decoded = decodeSimQuote(q.quote);
      expect(decoded.debug).toBe(true);
      expect(decoded.mrtd).toBe(SIM_DEBUG_MRTD);
    } finally {
      await sim.close();
    }
  });

  // Needs `pnpm -r build`. Skipped without dist, except in CI mode (SEALED_REQUIRE_CHAIN_TESTS=1), where it fails.
  const built = existsSync(join(import.meta.dirname, "../dist/sim.js"));
  it.skipIf(!built && process.env.SEALED_REQUIRE_CHAIN_TESTS !== "1")("runs as a CLI (node dist/sim.js)", async () => {
    expect(built, "dist/sim.js is missing: run pnpm -r build before the tests").toBe(true);
    const sock = join(dir, "cli.sock");
    const child = spawn(process.execPath, [join(import.meta.dirname, "../dist/sim.js"), "--app-compose", composePath, "--socket", sock], { stdio: ["ignore", "pipe", "pipe"] });
    try {
      const line = await new Promise<string>((ok, fail) => {
        child.stdout.once("data", (d) => ok(String(d)));
        child.once("exit", (code) => fail(new Error(`sim exited ${code}`)));
      });
      expect(JSON.parse(line).composeHash).toBe(sha256Hex(compose).slice(2));
      const q = await new DstackClient(parseEndpoint(sock)).getQuote(new Uint8Array(64).fill(1));
      expect(decodeSimQuote(q.quote).reportData).toBe("01".repeat(64));
    } finally {
      child.kill("SIGTERM");
    }
  });
});
