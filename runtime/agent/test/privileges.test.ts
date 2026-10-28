import { describe, expect, it } from "vitest";
import { silentLogger } from "../src/log.js";
import { dropPrivileges, parseRunAs } from "../src/privileges.js";

describe("privilege drop", () => {
  it("parses uid[:gid] and refuses root", () => {
    expect(parseRunAs("10001")).toEqual({ uid: 10001, gid: 10001 });
    expect(parseRunAs("10001:20002")).toEqual({ uid: 10001, gid: 20002 });
    expect(parseRunAs(undefined)).toBeUndefined();
    expect(() => parseRunAs("0")).toThrow("root");
    expect(() => parseRunAs("sealed")).toThrow("uid");
  });
  it("is a no-op when not running as root", async () => {
    if (process.getuid?.() === 0) return;
    expect(await dropPrivileges({ uid: 10001, gid: 10001 }, ["/nonexistent"], silentLogger)).toBe(false);
  });
});
