import { describe, expect, it } from "vitest";
import { settingsFromEnv } from "../src/settings.js";

describe("agent settings", () => {
  it("defaults to the in-VM paths of INTERFACES 11-15", () => {
    const s = settingsFromEnv({});
    expect(s).toMatchObject({
      listenHost: "0.0.0.0",
      listenPort: 7070,
      secretsDir: "/run/sealed/secrets",
      readyFile: "/run/sealed/ready",
      dataMount: "/mnt/sealed-data",
      diskMode: "luks",
      egressStatsUrl: "http://172.30.0.2:9100/v1/stats",
      reattestHours: 24,
    });
  });
  it("reads overrides and validates them", () => {
    const s = settingsFromEnv({ SEALED_LISTEN: "127.0.0.1:0", SEALED_DISK_MODE: "dir", SEALED_RUN_AS: "10001", SEALED_TEST_OVERRIDES: "1" });
    expect(s.listenPort).toBe(0);
    expect(s.diskMode).toBe("dir");
    expect(s.runAs).toBe("10001");
    expect(s.testOverrides).toBe(true);
    expect(() => settingsFromEnv({ SEALED_DISK_MODE: "zfs" })).toThrow();
    expect(() => settingsFromEnv({ SEALED_REATTEST_HOURS: "-1" })).toThrow();
  });
});
