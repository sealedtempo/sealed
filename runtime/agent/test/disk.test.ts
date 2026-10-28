import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type CommandResult, type CommandRunner, DirDisk, LuksDisk } from "../src/disk.js";
import { silentLogger } from "../src/log.js";

interface Call {
  cmd: string;
  args: string[];
  stdin?: Uint8Array;
}

/** A fake block device: tracks whether it is LUKS-formatted, mapped, has a filesystem, is mounted. */
function fakeDevice(initial: { luks?: boolean; foreign?: boolean; fs?: boolean } = {}) {
  const dev = { luks: !!initial.luks, foreign: !!initial.foreign, mapped: false, fs: !!initial.fs, key: undefined as string | undefined, mounted: false };
  const calls: Call[] = [];
  const ok: CommandResult = { code: 0, stdout: "", stderr: "" };
  const runner: CommandRunner = {
    async run(cmd, args, opts) {
      calls.push({ cmd, args, stdin: opts?.stdin });
      const sub = args[0];
      if (cmd === "cryptsetup" && sub === "isLuks") return dev.luks ? ok : { ...ok, code: 1 };
      if (cmd === "blkid") {
        const target = args[1] ?? "";
        const any = target.startsWith("/dev/mapper/") ? dev.fs : dev.luks || dev.foreign;
        return any ? ok : { ...ok, code: 2 };
      }
      if (cmd === "cryptsetup" && sub === "luksFormat") {
        dev.luks = true;
        dev.key = Buffer.from(opts?.stdin ?? []).toString("hex");
        return ok;
      }
      if (cmd === "cryptsetup" && sub === "status") return dev.mapped ? ok : { ...ok, code: 4 };
      if (cmd === "cryptsetup" && sub === "open") {
        if (Buffer.from(opts?.stdin ?? []).toString("hex") !== dev.key) return { code: 2, stdout: "", stderr: "No key available with this passphrase." };
        dev.mapped = true;
        return ok;
      }
      if (cmd === "mkfs.ext4") {
        dev.fs = true;
        return ok;
      }
      if (cmd === "mount") {
        dev.mounted = true;
        return ok;
      }
      return { code: 127, stdout: "", stderr: `unexpected ${cmd}` };
    },
  };
  return { dev, calls, runner };
}

describe("LUKS2 data disk", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-disk-"));
    await writeFile(join(dir, "mountinfo"), "");
  });
  afterEach(async () => rm(dir, { recursive: true, force: true }));
  const key = new Uint8Array(32).fill(9);
  const disk = (runner: CommandRunner) =>
    new LuksDisk({ device: "/dev/sdb", name: "sealed-data", mountPoint: join(dir, "mnt"), runner, mountInfoPath: join(dir, "mountinfo"), log: silentLogger });

  it("formats a blank disk, creates ext4 and mounts; the key only travels on stdin", async () => {
    const f = fakeDevice();
    await disk(f.runner).open(key);
    expect(f.calls.map((c) => `${c.cmd} ${c.args[0]}`)).toEqual([
      "cryptsetup isLuks", "blkid -p", "cryptsetup luksFormat", "cryptsetup status", "cryptsetup open", "mkfs.ext4 -q", "mount -t",
    ]);
    const format = f.calls.find((c) => c.args[0] === "luksFormat") as Call;
    expect(format.args).toContain("luks2");
    expect(format.args).toContain("--key-file");
    expect(format.args[format.args.indexOf("--key-file") + 1]).toBe("-");
    for (const c of f.calls) expect(c.args.join(" ")).not.toContain(Buffer.from(key).toString("hex"));
    expect(Buffer.from(format.stdin ?? []).equals(Buffer.from(key))).toBe(true);
    expect(f.dev.mounted).toBe(true);
  });

  it("unlocks an existing volume on reboot without formatting", async () => {
    const f = fakeDevice({ luks: true, fs: true });
    f.dev.key = Buffer.from(key).toString("hex");
    await disk(f.runner).open(key);
    const subs = f.calls.map((c) => `${c.cmd} ${c.args[0]}`);
    expect(subs).not.toContain("cryptsetup luksFormat");
    expect(subs).not.toContain("mkfs.ext4 -q");
    expect(subs).toContain("cryptsetup open");
  });

  it("fails with the wrong key and refuses to format foreign data", async () => {
    const wrong = fakeDevice({ luks: true, fs: true });
    wrong.dev.key = "00";
    await expect(disk(wrong.runner).open(key)).rejects.toThrow("cryptsetup open failed");
    const foreign = fakeDevice({ foreign: true });
    await expect(disk(foreign.runner).open(key)).rejects.toThrow("refusing to format");
    expect(foreign.calls.some((c) => c.args[0] === "luksFormat")).toBe(false);
  });

  it("is a no-op when already mounted", async () => {
    await writeFile(join(dir, "mountinfo"), `36 25 253:0 / ${join(dir, "mnt")} rw,nosuid,nodev - ext4 /dev/mapper/sealed-data rw\n`);
    const f = fakeDevice();
    await disk(f.runner).open(key);
    expect(f.calls).toEqual([]);
  });

  it("rejects keys that are not 32 bytes; DirDisk creates the directory", async () => {
    await expect(disk(fakeDevice().runner).open(new Uint8Array(16))).rejects.toThrow("32 bytes");
    await new DirDisk(join(dir, "plain")).open(key);
  });
});
