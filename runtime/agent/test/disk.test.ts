import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type CommandResult,
  type CommandRunner,
  deriveLuksKeys,
  DirDisk,
  LuksDisk,
  LuksHeaderError,
  parseCryptTable,
  parseMountInfo,
  spawnRunner,
  validateLuksHeader,
} from "../src/disk.js";
import { silentLogger } from "../src/log.js";

interface Call {
  cmd: string;
  args: string[];
  stdin?: Uint8Array;
  fds?: Uint8Array[];
}

const DEVICE = "/dev/sealed-data";
const DEV_ID = "8:16";
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** The JSON area `cryptsetup luksFormat` writes for the agent's parameters (cryptsetup 2.6). */
function goodHeader() {
  return {
    keyslots: {
      "0": {
        type: "luks2",
        key_size: 64,
        af: { type: "luks1", stripes: 4000, hash: "sha256" },
        area: { type: "raw", offset: "32768", size: "258048", encryption: "aes-xts-plain64", key_size: 64 },
        kdf: { type: "pbkdf2", hash: "sha256", iterations: 1000, salt: "c2FsdA==" },
      },
    },
    tokens: {},
    segments: { "0": { type: "crypt", offset: "16777216", size: "dynamic", iv_tweak: "0", encryption: "aes-xts-plain64", sector_size: 4096 } },
    digests: { "0": { type: "pbkdf2", keyslots: ["0"], segments: ["0"], hash: "sha256", iterations: 1000, salt: "c2FsdA==", digest: "ZGln" } },
    config: { json_size: "12288", keyslots_size: "16744448" },
  };
}

/**
 * A fake block device with cryptsetup, dmsetup, blkid, mkfs and mount. The header, the volume key a
 * passphrase unlocks and the resulting dm table are modelled, so a header the host crafted behaves
 * like the real thing: it may open, but with a cipher or key the agent did not choose.
 */
function fakeDevice(dir: string, initial: { luks?: { header: unknown; passphrase: string; volumeKey: string; cipher?: string }; foreign?: boolean; fs?: boolean; backing?: string } = {}) {
  const dev = {
    luks: initial.luks,
    foreign: !!initial.foreign,
    table: undefined as string | undefined,
    fs: !!initial.fs,
    mounted: false,
    closed: 0,
    backing: initial.backing ?? DEV_ID,
  };
  const calls: Call[] = [];
  const mountinfo = join(dir, "mountinfo");
  const ok: CommandResult = { code: 0, stdout: "", stderr: "" };
  const runner: CommandRunner = {
    async run(cmd, args, opts) {
      // Copies: the agent zeroes its key buffers once the disk is open.
      calls.push({ cmd, args, stdin: opts?.stdin && Uint8Array.from(opts.stdin), fds: opts?.fds?.map((f) => Uint8Array.from(f)) });
      const sub = args[0];
      if (cmd === "dmsetup" && sub === "table") return dev.table ? { ...ok, stdout: `${dev.table}\n` } : { code: 1, stdout: "", stderr: "Device does not exist." };
      if (cmd === "cryptsetup" && sub === "isLuks") return dev.luks ? ok : { ...ok, code: 1 };
      if (cmd === "blkid") {
        const target = args[1] ?? "";
        const any = target.startsWith("/dev/mapper/") ? dev.fs : !!dev.luks || dev.foreign;
        return any ? ok : { ...ok, code: 2 };
      }
      if (cmd === "cryptsetup" && sub === "luksFormat") {
        dev.luks = { header: goodHeader(), passphrase: hex(opts?.stdin ?? new Uint8Array()), volumeKey: hex(opts?.fds?.[0] ?? new Uint8Array()) };
        return ok;
      }
      if (cmd === "cryptsetup" && sub === "luksDump") return { ...ok, stdout: JSON.stringify(dev.luks?.header ?? {}) };
      if (cmd === "cryptsetup" && sub === "open") {
        if (!dev.luks || hex(opts?.stdin ?? new Uint8Array()) !== dev.luks.passphrase) return { code: 2, stdout: "", stderr: "No key available with this passphrase." };
        const keyring = !args.includes("--disable-keyring");
        dev.table = `0 20938752 crypt ${dev.luks.cipher ?? "aes-xts-plain64"} ${keyring ? ":64:logon:cryptsetup:x-d0" : dev.luks.volumeKey} 0 ${dev.backing} 32768 1 sector_size:4096`;
        return ok;
      }
      if (cmd === "cryptsetup" && sub === "close") {
        dev.table = undefined;
        dev.closed++;
        return ok;
      }
      if (cmd === "mkfs.ext4") {
        dev.fs = true;
        return ok;
      }
      if (cmd === "mount") {
        dev.mounted = true;
        await writeFile(mountinfo, `${bindLine(args.at(-1) as string)}37 36 253:0 / ${args.at(-1)} rw,nosuid,nodev shared:2 - ext4 /dev/mapper/sealed-data rw\n`);
        return ok;
      }
      return { code: 127, stdout: "", stderr: `unexpected ${cmd}` };
    },
  };
  return { dev, calls, runner };
}

/** The composer's bind mount of the host data directory at the same path (rshared), as the agent's mountinfo shows it. */
const bindLine = (mnt: string) => `1530 1510 254:1 /mnt/sealed-data ${mnt} rw,relatime shared:12 master:1 - ext4 /dev/mapper/dstack_data rw\n`;

describe("LUKS2 data disk", () => {
  let dir: string;
  let mnt: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-disk-"));
    mnt = join(dir, "mnt");
    await writeFile(join(dir, "mountinfo"), bindLine(mnt));
  });
  afterEach(async () => rm(dir, { recursive: true, force: true }));
  const diskKey = new Uint8Array(32).fill(9);
  const keys = deriveLuksKeys(diskKey);
  const disk = (runner: CommandRunner) =>
    new LuksDisk({ device: DEVICE, name: "sealed-data", mountPoint: mnt, runner, mountInfoPath: join(dir, "mountinfo"), deviceId: async () => DEV_ID, log: silentLogger });
  const ours = () => ({ header: goodHeader(), passphrase: hex(keys.passphrase), volumeKey: hex(keys.volumeKey) });

  it("derives the passphrase and the volume key from diskKey (stable across reboots)", () => {
    const again = deriveLuksKeys(new Uint8Array(32).fill(9));
    expect(again.volumeKey.length).toBe(64);
    expect(hex(again.volumeKey)).toBe(hex(keys.volumeKey));
    expect(hex(again.passphrase)).not.toBe(hex(diskKey));
    expect(hex(deriveLuksKeys(new Uint8Array(32).fill(8)).volumeKey)).not.toBe(hex(keys.volumeKey));
    // Frozen: changing the derivation would make every existing data disk unreadable.
    expect(hex(again.passphrase)).toBe("bc24f9ee2c155e2364276f50432c2b25460f92c5b0c9980243b1f8d7905e9521");
    expect(hex(again.volumeKey)).toBe("6fb774e39ba4e15edbee4166b432a06044a4d1037642bf2dfd83c10671fa8b0321ad4ccb723c83c7d6de2eb6e7aaa694f548eac75ba759f83ce8fb95f8d15e4a");
  });

  it("formats a blank disk with the derived volume key, checks the result, creates ext4 and mounts; keys never in argv", async () => {
    const f = fakeDevice(dir);
    await disk(f.runner).open(diskKey);
    expect(f.calls.map((c) => `${c.cmd} ${c.args[0]}`)).toEqual([
      "dmsetup table",
      "cryptsetup isLuks",
      "blkid -p",
      "cryptsetup luksFormat",
      "cryptsetup luksDump",
      "cryptsetup open",
      "dmsetup table",
      "mkfs.ext4 -q",
      "mount -t",
    ]);
    const format = f.calls.find((c) => c.args[0] === "luksFormat") as Call;
    expect(format.args).toEqual(expect.arrayContaining(["luks2", "aes-xts-plain64", "--volume-key-file", "/dev/fd/3", "--key-file", "-"]));
    expect(hex(format.stdin ?? new Uint8Array())).toBe(hex(keys.passphrase));
    expect(hex(format.fds?.[0] ?? new Uint8Array())).toBe(hex(keys.volumeKey));
    const open = f.calls.find((c) => c.args[0] === "open") as Call;
    expect(open.args).toContain("--disable-keyring");
    for (const c of f.calls) {
      const argv = c.args.join(" ");
      for (const secret of [diskKey, keys.passphrase, keys.volumeKey]) expect(argv).not.toContain(hex(secret));
    }
    expect(f.dev.mounted).toBe(true);
  });

  it("unlocks an existing volume on reboot without formatting", async () => {
    const f = fakeDevice(dir, { luks: ours(), fs: true });
    await disk(f.runner).open(diskKey);
    const subs = f.calls.map((c) => `${c.cmd} ${c.args[0]}`);
    expect(subs).not.toContain("cryptsetup luksFormat");
    expect(subs).not.toContain("mkfs.ext4 -q");
    expect(subs).toContain("cryptsetup open");
    expect(f.dev.mounted).toBe(true);
  });

  // Review finding (critical): the composer bind-mounts /mnt/sealed-data at the same path, which used to
  // count as "already mounted", so the disk was never unlocked.
  it("the composer's bind mount at the mount point does not count as mounted", async () => {
    expect(parseMountInfo(bindLine(mnt))).toEqual([{ mountPoint: mnt, fstype: "ext4", source: "/dev/mapper/dstack_data" }]);
    const f = fakeDevice(dir, { luks: ours(), fs: true });
    await disk(f.runner).open(diskKey);
    expect(f.calls.some((c) => c.cmd === "cryptsetup" && c.args[0] === "open")).toBe(true);
    expect(f.calls.some((c) => c.cmd === "mount")).toBe(true);
  });

  it("is a no-op when the encrypted filesystem is already mounted on top (agent restart)", async () => {
    const f = fakeDevice(dir, { luks: ours(), fs: true });
    f.dev.table = `0 20938752 crypt aes-xts-plain64 ${hex(keys.volumeKey)} 0 ${DEV_ID} 32768`;
    await writeFile(join(dir, "mountinfo"), `${bindLine(mnt)}1531 1530 253:0 / ${mnt} rw,nosuid,nodev shared:13 - ext4 /dev/mapper/sealed-data rw\n`);
    await disk(f.runner).open(diskKey);
    expect(f.calls.map((c) => `${c.cmd} ${c.args[0]}`)).toEqual(["dmsetup table"]);
  });

  it("an existing mapping that is not exactly ours fails boot (wrong key, keyring, other device)", async () => {
    for (const table of [
      `0 1 crypt aes-xts-plain64 ${"ab".repeat(64)} 0 ${DEV_ID} 32768`,
      `0 1 crypt aes-xts-plain64 :64:logon:cryptsetup:x-d0 0 ${DEV_ID} 32768`,
      `0 1 crypt aes-xts-plain64 ${hex(keys.volumeKey)} 0 8:32 32768`,
      `0 1 crypt cipher_null-ecb - 0 ${DEV_ID} 32768`,
      `0 1 linear 8:16 0`,
    ]) {
      const f = fakeDevice(dir, { luks: ours(), fs: true });
      f.dev.table = table;
      await expect(disk(f.runner).open(diskKey)).rejects.toThrow(LuksHeaderError);
      expect(f.calls.some((c) => c.cmd === "mount")).toBe(false);
    }
  });

  // Review finding (high): a host-supplied header was trusted. cipher_null keyslots open with any
  // passphrase and give the host the volume key; a cipher_null segment writes plaintext.
  it("rejects crafted headers before unlocking: cipher_null segment or keyslot, extra keyslots, tokens, integrity, reencryption", async () => {
    const variants: [string, (h: ReturnType<typeof goodHeader>) => unknown][] = [
      ["cipher_null segment", (h) => ((h.segments["0"].encryption = "cipher_null-ecb"), h)],
      ["cipher_null keyslot", (h) => ((h.keyslots["0"].area.encryption = "cipher_null-ecb"), h)],
      ["second keyslot", (h) => ({ ...h, keyslots: { ...h.keyslots, "1": h.keyslots["0"] } })],
      ["token", (h) => ({ ...h, tokens: { "0": { type: "luks2-keyring", keyslots: ["0"] } } })],
      ["integrity", (h) => ((h.segments["0"] as Record<string, unknown>).integrity = { type: "hmac(sha256)" }, h)],
      ["reencrypt", (h) => ({ ...h, config: { ...h.config, requirements: { mandatory: ["online-reencrypt-v2"] } } })],
      ["argon", (h) => ((h.keyslots["0"].kdf.type = "argon2id"), h)],
      ["128-bit", (h) => ((h.keyslots["0"].key_size = 32), h)],
    ];
    for (const [what, mutate] of variants) {
      const f = fakeDevice(dir, { luks: { ...ours(), header: mutate(goodHeader()) }, fs: true });
      await expect(disk(f.runner).open(diskKey), what).rejects.toThrow(/untrusted LUKS2 header/);
      expect(f.calls.some((c) => c.args[0] === "open"), what).toBe(false);
    }
    expect(() => validateLuksHeader(goodHeader())).not.toThrow();
  });

  it("a well-formed header whose volume key is not derived from diskKey is closed again and never mounted", async () => {
    // The host formatted the disk itself with a volume key it knows and a keyslot for some passphrase
    // it could make us use: the live table shows a key that is not ours.
    const f = fakeDevice(dir, { luks: { ...ours(), volumeKey: "cd".repeat(64) }, fs: true });
    await expect(disk(f.runner).open(diskKey)).rejects.toThrow("volume key is not the one derived");
    expect(f.dev.closed).toBe(1);
    expect(f.dev.table).toBeUndefined();
    expect(f.calls.some((c) => c.cmd === "mount")).toBe(false);
    const cipher = fakeDevice(dir, { luks: { ...ours(), cipher: "cipher_null-ecb" }, fs: true });
    await expect(disk(cipher.runner).open(diskKey)).rejects.toThrow("cipher is cipher_null-ecb");
    expect(cipher.dev.closed).toBe(1);
  });

  it("fails with the wrong key and refuses to format foreign data", async () => {
    const wrong = fakeDevice(dir, { luks: { ...ours(), passphrase: "00" }, fs: true });
    await expect(disk(wrong.runner).open(diskKey)).rejects.toThrow("cryptsetup open failed");
    const foreign = fakeDevice(dir, { foreign: true });
    await expect(disk(foreign.runner).open(diskKey)).rejects.toThrow("refusing to format");
    expect(foreign.calls.some((c) => c.args[0] === "luksFormat")).toBe(false);
  });

  it("parses dm tables and mountinfo escapes", () => {
    expect(parseCryptTable(`0 8 crypt aes-xts-plain64 ${"aa".repeat(64)} 0 8:16 32768 2 allow_discards sector_size:4096\n`)).toEqual({
      cipher: "aes-xts-plain64",
      key: "aa".repeat(64),
      ivOffset: "0",
      device: "8:16",
      options: ["allow_discards", "sector_size:4096"],
    });
    expect(() => parseCryptTable("0 8 crypt a b 0 8:16 0\n8 8 crypt a b 0 8:16 0")).toThrow("one dm target");
    expect(parseMountInfo("36 25 8:1 / /mnt/with\\040space rw - ext4 /dev/x rw")[0]?.mountPoint).toBe("/mnt/with space");
  });

  it("rejects keys that are not 32 bytes; DirDisk creates the directory", async () => {
    await expect(disk(fakeDevice(dir).runner).open(new Uint8Array(16))).rejects.toThrow("32 bytes");
    await new DirDisk(join(dir, "plain")).open(diskKey);
  });

  it("the spawn runner feeds stdin and extra fds through pipes", async () => {
    const r = await spawnRunner.run("sh", ["-c", "cat; cat /dev/fd/3"], { stdin: Buffer.from("in:"), fds: [Buffer.from("fd3")] });
    expect(r).toMatchObject({ code: 0, stdout: "in:fd3" });
  });
});
