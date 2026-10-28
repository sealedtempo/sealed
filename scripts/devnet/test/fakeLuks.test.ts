// The fake block-device tools against the agent's real LuksDisk: first boot formats, a reboot opens the same
// volume only with the same diskKey, and an agent restart inside one boot finds its mapping and mount.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LuksDisk } from "@sealed/agent/dist/src/disk.js";
import { silentLogger } from "@sealed/agent/dist/src/log.js";
import { afterEach, describe, expect, it } from "vitest";
import { FakeLuksRunner, mountInfoEscape } from "../src/fakeLuks.ts";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function setup() {
  // A space in the path, as in the operator's workspace: mountinfo escapes it as \040.
  const dir = mkdtempSync(join(tmpdir(), "devnet luks "));
  dirs.push(dir);
  const device = join(dir, "sealed-data");
  writeFileSync(device, "");
  const o = { statePath: join(dir, "disk.json"), device, mountInfoPath: join(dir, "mountinfo"), deviceId: "253:7" };
  const mountPoint = join(dir, "mnt", "sealed-data");
  const boot = () => {
    const runner = new FakeLuksRunner(o);
    const disk = new LuksDisk({ device, name: "sealed-data", mountPoint, runner, mountInfoPath: o.mountInfoPath, deviceId: async () => o.deviceId, log: silentLogger });
    return { runner, disk };
  };
  return { o, mountPoint, boot };
}

const key = (b: number) => new Uint8Array(32).fill(b);

describe("FakeLuksRunner with the agent's LuksDisk", () => {
  it("formats on first boot and opens the same volume after a reboot", async () => {
    const t = setup();
    const first = t.boot();
    await first.disk.open(key(1));
    expect(first.runner.state.ops).toEqual(["luksFormat", "open", "mkfs.ext4", "mount"]);
    expect(readFileSync(t.o.mountInfoPath, "utf8")).toContain(`${mountInfoEscape(t.mountPoint)} rw,nosuid,nodev`);
    expect(mountInfoEscape("/a b\\c")).toBe("/a\\040b\\134c");

    // Agent restart in the same boot (a new process, kernel state kept): the mapping and mount are found and
    // checked, nothing runs again.
    const sameBoot = new FakeLuksRunner({ ...t.o, newBoot: false });
    await new LuksDisk({ device: t.o.device, name: "sealed-data", mountPoint: t.mountPoint, runner: sameBoot, mountInfoPath: t.o.mountInfoPath, deviceId: async () => t.o.deviceId, log: silentLogger }).open(key(1));
    expect(sameBoot.state.ops).toEqual(["luksFormat", "open", "mkfs.ext4", "mount"]);
    // ... and with another key the live table's volume key does not match.
    await expect(
      new LuksDisk({ device: t.o.device, name: "sealed-data", mountPoint: t.mountPoint, runner: new FakeLuksRunner({ ...t.o, newBoot: false }), mountInfoPath: t.o.mountInfoPath, deviceId: async () => t.o.deviceId, log: silentLogger }).open(key(9)),
    ).rejects.toThrow("not the one derived from diskKey");

    // Reboot: a new runner (no mappings, empty mountinfo), the same disk state.
    const second = t.boot();
    await second.disk.open(key(1));
    expect(second.runner.state.ops).toEqual(["luksFormat", "open", "mkfs.ext4", "mount", "open", "mount"]);
  });

  it("refuses another diskKey after a reboot", async () => {
    const t = setup();
    await t.boot().disk.open(key(1));
    const other = t.boot();
    await expect(other.disk.open(key(2))).rejects.toThrow("No key available with this passphrase");
    expect(other.runner.state.ops.at(-1)).toBe("open:wrong-passphrase");
  });

  it("answers unknown commands with a failure", async () => {
    const t = setup();
    const r = await t.boot().runner.run("cryptsetup", ["resize", "x"]);
    expect(r.code).toBe(127);
  });
});
