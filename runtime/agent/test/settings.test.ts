import { parseDefaults } from "@sealed/core";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { settlementIntervalMs } from "../src/agent.js";
import { settingsFromEnv } from "../src/settings.js";

describe("agent settings", () => {
  it("defaults to the paths the composer gives sealed-agent", () => {
    const s = settingsFromEnv({});
    expect(s).toMatchObject({
      configPath: "/etc/sealed/config.json",
      stackPath: "/etc/sealed/stack.json",
      caddyfilePath: "/etc/sealed/caddy/Caddyfile",
      caddyfilePaymentNeededPath: "/etc/sealed/caddy/Caddyfile.payment-needed",
      listenHost: "0.0.0.0",
      listenPort: 7070,
      secretsDir: "/run/sealed/secrets",
      readyDir: "/run/sealed/ready",
      dataMount: "/mnt/sealed-data",
      dataDevice: "/dev/sealed-data",
      caddyAdminSocket: "/run/sealed/caddy-admin/admin.sock",
      dstackEndpoint: "/var/run/dstack.sock",
      diskMode: "luks",
      egressStatsUrl: "http://172.30.0.2:9100/v1/stats",
      reattestHours: 24,
      devSim: false,
      requireTmpfs: true,
    });
  });
  it("reads overrides and validates them", () => {
    const s = settingsFromEnv({ PORT: "0", SEALED_LISTEN_HOST: "127.0.0.1", SEALED_DEV_SIM: "1", SEALED_DISK_MODE: "dir", SEALED_RUN_AS: "10001", SEALED_TEST_OVERRIDES: "1" });
    expect(s.listenPort).toBe(0);
    expect(s.listenHost).toBe("127.0.0.1");
    expect(s.diskMode).toBe("dir");
    expect(s.requireTmpfs).toBe(false);
    expect(s.runAs).toBe("10001");
    expect(s.testOverrides).toBe(true);
    expect(() => settingsFromEnv({ SEALED_DISK_MODE: "zfs" })).toThrow();
    expect(() => settingsFromEnv({ SEALED_REATTEST_HOURS: "-1" })).toThrow();
    expect(() => settingsFromEnv({ PORT: "70000" })).toThrow();
  });
  it("uses the simulator and a plain data directory only in dev sim mode (INTERFACES 13)", () => {
    expect(() => settingsFromEnv({ DSTACK_SIMULATOR_ENDPOINT: "/tmp/sim.sock" })).toThrow("SEALED_DEV_SIM");
    expect(() => settingsFromEnv({ SEALED_DISK_MODE: "dir" })).toThrow("SEALED_DEV_SIM");
    expect(settingsFromEnv({ SEALED_DEV_SIM: "1", DSTACK_SIMULATOR_ENDPOINT: "/tmp/sim.sock" }).dstackEndpoint).toBe("/tmp/sim.sock");
    expect(settingsFromEnv({ DSTACK_SOCKET: "/run/dstack.sock" }).dstackEndpoint).toBe("/run/dstack.sock");
  });
  // Regression (devnet-e2e): a local devnet could only settle every intervalMinutes (at least a minute), so a
  // full payment round trip took minutes. test_overrides.settlement_interval_seconds speeds up the timer, and
  // only for a dev simulator agent with SEALED_TEST_OVERRIDES=1.
  it("settles every intervalMinutes unless a dev sim agent has test_overrides.settlement_interval_seconds", () => {
    const yaml = readFileSync(join(import.meta.dirname, "../../../config/defaults.yaml"), "utf8").replace(
      "test_overrides: {",
      "test_overrides: {settlement_interval_seconds: 3, ",
    );
    const cfg = { settlement: { intervalMinutes: 2 } };
    const withOverrides = parseDefaults(yaml, { testOverrides: true });
    const plain = parseDefaults(yaml, { testOverrides: false });
    expect(settlementIntervalMs(cfg, withOverrides, { devSim: true, testOverrides: true })).toBe(3000);
    expect(settlementIntervalMs(cfg, withOverrides, { devSim: false, testOverrides: true })).toBe(120_000);
    expect(settlementIntervalMs(cfg, plain, { devSim: true, testOverrides: false })).toBe(120_000);
    expect(settlementIntervalMs(cfg, parseDefaults(yaml.replace("settlement_interval_seconds: 3", "settlement_interval_seconds: 0"), { testOverrides: true }), { devSim: true, testOverrides: true })).toBe(120_000);
  });
});
