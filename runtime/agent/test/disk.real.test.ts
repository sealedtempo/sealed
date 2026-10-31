// Real dm-crypt for the LUKS2 data disk (G18; spec 5.6 step 3 and 5.9). disk.test.ts drives LuksDisk through a
// fake runner that encodes what the tools print. This suite runs the same class with the real process runner on
// 64 MiB loop devices, so those assumptions meet cryptsetup 2.6.1, dmsetup, blkid, mkfs.ext4 and mount: the
// luksDump JSON shape, the dm table format, the volume key read from fd 3, blkid's exit codes and the mapper path
// in mountinfo.
//
// Opt-in: SEALED_REAL_LUKS=1, as root on Linux. .github/workflows/agent-luks.yml runs it in a privileged
// container made from the agent image's base with the agent image's Debian package pins
// (test/luks-container.sh, which also shows the command for a local run). Without SEALED_REAL_LUKS only the
// pin check at the end runs.
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  blockDeviceId,
  type CommandResult,
  deriveLuksKeys,
  LuksDisk,
  LuksHeaderError,
  parseCryptTable,
  parseMountInfo,
  spawnRunner,
  validateLuksHeader,
} from "../src/disk.js";
import { silentLogger } from "../src/log.js";

const REAL = process.env.SEALED_REAL_LUKS === "1";
const REPO = join(import.meta.dirname, "../../..");
const MiB = 1024 * 1024;
const KEY = new Uint8Array(32).fill(0x5d);
const OTHER_KEY = new Uint8Array(32).fill(0x5e);
// Distinctive, so finding it (or not) in raw device bytes means something, and under 1 KiB, so it sits in one
// filesystem block whatever block size mkfs picks.
const MARKER = "sealed-real-luks-plaintext-marker:".repeat(28);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

type RunOpts = { stdin?: Uint8Array; fds?: Uint8Array[] };
const run = (cmd: string, args: string[], opts?: RunOpts): Promise<CommandResult> => spawnRunner.run(cmd, args, opts);
async function must(cmd: string, args: string[], opts?: RunOpts): Promise<CommandResult> {
  const r = await run(cmd, args, opts);
  if (r.code !== 0) throw new Error(`${cmd} ${args.join(" ")} failed (${r.code}): ${r.stderr.trim()}`);
  return r;
}

/** The error a promise rejects with (fails the test when it resolves). */
async function failure(p: Promise<unknown>): Promise<Error> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  if (!(err instanceof Error)) throw new Error(`expected a rejection, got ${String(err)}`);
  return err;
}

describe.skipIf(!REAL)("LUKS2 data disk on real dm-crypt (SEALED_REAL_LUKS=1)", () => {
  const NAME = `sealed-real-${process.pid}`;
  const NAME_B = `${NAME}-b`;
  let dir: string;
  let workMounted = false;
  let devA: string;
  let devB: string;
  let imgA: string;
  let mntA: string;
  let mntB: string;
  const loops: string[] = [];
  const keys = deriveLuksKeys(KEY.slice());

  const disk = (device: string, name: string, mountPoint: string) => new LuksDisk({ device, name, mountPoint, log: silentLogger });
  const mountsAt = async (mnt: string) => parseMountInfo(await readFile("/proc/self/mountinfo", "utf8")).filter((e) => e.mountPoint === mnt);
  const topMount = async (mnt: string) => (await mountsAt(mnt)).at(-1);
  /** The live table of a mapping (key included), or undefined. */
  const table = async (name: string) => {
    const r = await run("dmsetup", ["table", "--showkeys", name]);
    return r.code === 0 ? r.stdout : undefined;
  };
  const luksUUID = async (dev: string) => (await must("cryptsetup", ["luksUUID", dev])).stdout.trim();
  const blkidType = async (dev: string) => (await run("blkid", ["-p", "-s", "TYPE", "-o", "value", dev])).stdout.trim();
  const openByHand = (dev: string, name: string, keyring = false) =>
    must("cryptsetup", ["open", "--type", "luks2", ...(keyring ? [] : ["--disable-keyring"]), "--key-file", "-", dev, name], { stdin: keys.passphrase });
  /** Unmounts and closes what the agent (or a test) left open. */
  async function teardown(name: string, mnt: string) {
    while ((await topMount(mnt))?.source === `/dev/mapper/${name}`) await must("umount", [mnt]);
    if (await table(name)) await must("cryptsetup", ["close", name]);
  }

  /** A container sees only the loop nodes that existed when it started, so a node the kernel just added is made here. */
  async function attachLoop(file: string): Promise<string> {
    let last = "";
    for (let i = 0; i < 5; i++) {
      const dev = (await must("losetup", ["--find"])).stdout.trim();
      const n = /^\/dev\/loop(\d+)$/.exec(dev)?.[1];
      if (n === undefined) throw new Error(`losetup --find printed "${dev}"`);
      if (!existsSync(dev)) {
        const [major, minor] = (await readFile(`/sys/block/loop${n}/dev`, "utf8").catch(() => `7:${n}`)).trim().split(":") as [string, string];
        await must("mknod", ["-m", "0660", dev, "b", major, minor]);
      }
      const r = await run("losetup", [dev, file]);
      if (r.code === 0) {
        loops.push(dev);
        return dev;
      }
      last = r.stderr.trim();
    }
    throw new Error(`could not attach a loop device: ${last}`);
  }

  beforeAll(async () => {
    if (process.platform !== "linux" || process.getuid?.() !== 0) {
      throw new Error("SEALED_REAL_LUKS=1 needs root on Linux with cryptsetup, dmsetup, util-linux and e2fsprogs (see test/luks-container.sh)");
    }
    dir = await mkdtemp(join(tmpdir(), "sealed-real-luks-"));
    // The images live on a tmpfs of their own, so loop devices never sit on the container's overlay filesystem.
    await must("mount", ["-t", "tmpfs", "-o", "size=256m,mode=0700", "sealed-real-luks", dir]);
    workMounted = true;
    imgA = join(dir, "a.img");
    const imgB = join(dir, "b.img");
    for (const img of [imgA, imgB]) {
      const f = await open(img, "w");
      await f.truncate(64 * MiB);
      await f.close();
    }
    mntA = join(dir, "mnt-a");
    mntB = join(dir, "mnt-b");
    await mkdir(mntA);
    await mkdir(mntB);
    devA = await attachLoop(imgA);
    devB = await attachLoop(imgB);
  });

  afterAll(async () => {
    if (!dir) return;
    for (const [name, mnt] of [
      [NAME, mntA],
      [NAME, mntB],
      [NAME_B, mntB],
    ] as const) {
      await teardown(name, mnt).catch(() => undefined);
    }
    for (const dev of loops) await run("losetup", ["-d", dev]);
    if (workMounted) await run("umount", [dir]);
    await rm(dir, { recursive: true, force: true });
  });

  it("runs the cryptsetup the agent image pins", async () => {
    const pin = /cryptsetup-bin=(\S+)/.exec(await readFile(join(REPO, "runtime/agent/Dockerfile"), "utf8"))?.[1];
    expect(pin).toBe("2:2.6.1-4~deb12u2");
    expect((await must("dpkg-query", ["-W", "-f", "${Version}", "cryptsetup-bin"])).stdout).toBe(pin);
    expect((await must("cryptsetup", ["--version"])).stdout).toMatch(/^cryptsetup 2\.6\.1\b/);
  });

  it("formats a blank device: the header, the dm table and mountinfo are what disk.ts checks", async () => {
    expect((await run("blkid", ["-p", devA])).code).toBe(2);
    await disk(devA, NAME, mntA).open(KEY);

    // luksDump --dump-json-metadata is the shape validateLuksHeader accepts.
    const meta = JSON.parse((await must("cryptsetup", ["luksDump", "--dump-json-metadata", devA])).stdout);
    expect(() => validateLuksHeader(meta)).not.toThrow();
    expect(meta.keyslots["0"]).toMatchObject({ type: "luks2", key_size: 64, kdf: { type: "pbkdf2", hash: "sha256", iterations: 1000 } });
    expect(meta.segments["0"]).toMatchObject({ type: "crypt", encryption: "aes-xts-plain64", iv_tweak: "0", size: "dynamic" });
    // blkid sees the LUKS2 label the agent sets.
    expect((await must("blkid", ["-p", "-s", "LABEL", "-o", "value", devA])).stdout.trim()).toBe("sealed-data");

    // The live table holds the volume key the agent fed on fd 3, on the loop device's major:minor.
    const t = parseCryptTable((await table(NAME)) as string);
    expect(t.cipher).toBe("aes-xts-plain64");
    expect(t.key).toBe(hex(keys.volumeKey));
    expect(t.ivOffset).toBe("0");
    const sysfs = (await readFile(`/sys/block/${devA.slice("/dev/".length)}/dev`, "utf8")).trim();
    expect(t.device).toBe(sysfs);
    expect(await blockDeviceId(devA)).toBe(sysfs);

    // Mounted ext4 from the mapper path, nodev and nosuid.
    expect(await topMount(mntA)).toEqual({ mountPoint: mntA, fstype: "ext4", source: `/dev/mapper/${NAME}` });
    const line = (await readFile("/proc/self/mountinfo", "utf8")).split("\n").filter((l) => l.split(" ")[4] === mntA).at(-1) ?? "";
    expect(line.split(" ")[5]?.split(",")).toEqual(expect.arrayContaining(["nodev", "nosuid"]));
    expect(await blkidType(`/dev/mapper/${NAME}`)).toBe("ext4");
    await writeFile(join(mntA, "marker.txt"), MARKER);
  });

  it("a second open in the same boot (agent restart) accepts its own mapping and mount", async () => {
    await disk(devA, NAME, mntA).open(KEY);
    expect((await mountsAt(mntA)).filter((e) => e.source === `/dev/mapper/${NAME}`)).toHaveLength(1);
    expect(await readFile(join(mntA, "marker.txt"), "utf8")).toBe(MARKER);
  });

  it("after close the device holds only ciphertext; reopening mounts the same data without formatting", async () => {
    const uuid = await luksUUID(devA);
    await must("umount", [mntA]);
    // Control: the plaintext is visible through the mapping...
    expect((await readFile(`/dev/mapper/${NAME}`)).includes(Buffer.from(MARKER))).toBe(true);
    await must("cryptsetup", ["close", NAME]);
    expect(await table(NAME)).toBeUndefined();
    // ...and nowhere in the backing bytes.
    expect((await readFile(imgA)).includes(Buffer.from(MARKER))).toBe(false);

    await disk(devA, NAME, mntA).open(KEY);
    expect(await readFile(join(mntA, "marker.txt"), "utf8")).toBe(MARKER);
    expect(await luksUUID(devA)).toBe(uuid);
  });

  it("a wrong key is refused and the volume is left as it was", async () => {
    const uuid = await luksUUID(devA);
    await teardown(NAME, mntA);
    const err = await failure(disk(devA, NAME, mntA).open(OTHER_KEY));
    expect(err.message).toMatch(/^cryptsetup open failed \(2\)/);
    expect(await table(NAME)).toBeUndefined();
    expect(await topMount(mntA)).toBeUndefined();
    expect(await luksUUID(devA)).toBe(uuid);
  });

  it("a header tampered without any key (a token, a keyslot priority) is refused before unlocking", async () => {
    const backup = join(dir, "header-a-1.img");
    await must("cryptsetup", ["luksHeaderBackup", devA, "--header-backup-file", backup]);
    const token = join(dir, "token.json");
    await writeFile(token, JSON.stringify({ type: "sealed-test", keyslots: ["0"] }));
    const tampers: [string, string[], RegExp][] = [
      ["token", ["token", "import", "--json-file", token, devA], /tokens are not allowed/],
      ["priority", ["config", "--priority", "prefer", "--key-slot", "0", devA], /keyslot priority/],
    ];
    for (const [what, args, msg] of tampers) {
      await must("cryptsetup", args);
      const err = await failure(disk(devA, NAME, mntA).open(KEY));
      expect(err, what).toBeInstanceOf(LuksHeaderError);
      expect(err.message, what).toMatch(msg);
      expect(await table(NAME), what).toBeUndefined();
      await must("cryptsetup", ["luksHeaderRestore", "--batch-mode", devA, "--header-backup-file", backup]);
    }
    await disk(devA, NAME, mntA).open(KEY);
    expect(await readFile(join(mntA, "marker.txt"), "utf8")).toBe(MARKER);
  });

  it("a header whose checksums fail in both copies is refused, and the device is not reformatted", async () => {
    await teardown(NAME, mntA);
    const backup = join(dir, "header-a-2.img");
    await must("cryptsetup", ["luksHeaderBackup", devA, "--header-backup-file", backup]);
    const meta = JSON.parse((await must("cryptsetup", ["luksDump", "--dump-json-metadata", devA])).stdout) as { config: { json_size: string }; segments: { "0": { offset: string } } };
    const hdrSize = 4096 + Number(meta.config.json_size);
    const dataOffset = Number(meta.segments["0"].offset);
    const digest = async () => createHash("sha256").update((await readFile(imgA)).subarray(dataOffset)).digest("hex");
    const before = await digest();
    // One byte of the JSON area of the primary and of the secondary header ('{"keyslots"' becomes '{"Keyslots"').
    const f = await open(devA, "r+");
    for (const at of [4096 + 2, hdrSize + 4096 + 2]) await f.write(Buffer.from("K"), 0, 1, at);
    await f.sync();
    await f.close();
    expect((await run("cryptsetup", ["isLuks", devA])).code).not.toBe(0);

    const err = await failure(disk(devA, NAME, mntA).open(KEY));
    expect(err.message).toMatch(/^refusing to format .*: it holds data that is not a LUKS2 volume$/);
    expect(await table(NAME)).toBeUndefined();
    expect(await digest()).toBe(before);

    await must("cryptsetup", ["luksHeaderRestore", "--batch-mode", devA, "--header-backup-file", backup]);
    await disk(devA, NAME, mntA).open(KEY);
    expect(await readFile(join(mntA, "marker.txt"), "utf8")).toBe(MARKER);
  });

  it("a mapping opened through the kernel keyring is refused", async () => {
    await teardown(NAME, mntA);
    await openByHand(devA, NAME, true);
    // cryptsetup's default for LUKS2: the table names a keyring key, so the agent cannot compare the volume key.
    expect(parseCryptTable((await table(NAME)) as string).key).toMatch(/^:64:logon:cryptsetup:/);
    const err = await failure(disk(devA, NAME, mntA).open(KEY));
    expect(err).toBeInstanceOf(LuksHeaderError);
    expect(err.message).toMatch(/kernel keyring/);
    expect(await topMount(mntA)).toBeUndefined();
    await teardown(NAME, mntA);
  });

  it("a mapping of the agent's name on another device is refused", async () => {
    await disk(devB, NAME, mntB).open(KEY);
    await must("umount", [mntB]);
    const err = await failure(disk(devA, NAME, mntA).open(KEY));
    expect(err).toBeInstanceOf(LuksHeaderError);
    expect(err.message).toMatch(new RegExp(`backing device \\S+ is not ${devA} \\(${await blockDeviceId(devA)}\\)`));
    expect(await topMount(mntA)).toBeUndefined();
    await teardown(NAME, mntB);
  });

  it("an established volume that shows no filesystem is closed and left untouched", async () => {
    // devB was formatted by the agent in the previous test; wipe the ext4 superblock inside it.
    const uuid = await luksUUID(devB);
    await openByHand(devB, NAME_B);
    await must("dd", ["if=/dev/zero", `of=/dev/mapper/${NAME_B}`, "bs=1M", "count=1", "conv=fsync", "status=none"]);
    expect((await run("blkid", ["-p", `/dev/mapper/${NAME_B}`])).code).toBe(2);
    await must("cryptsetup", ["close", NAME_B]);

    const err = await failure(disk(devB, NAME_B, mntB).open(KEY));
    expect(err.message).toMatch(/the existing LUKS2 volume holds no filesystem; it is left untouched/);
    expect(await table(NAME_B)).toBeUndefined();
    expect(await luksUUID(devB)).toBe(uuid);
    await openByHand(devB, NAME_B);
    expect((await run("blkid", ["-p", `/dev/mapper/${NAME_B}`])).code).toBe(2);
    await must("cryptsetup", ["close", NAME_B]);
  });

  it("a device that holds another filesystem is never formatted", async () => {
    await must("dd", ["if=/dev/zero", `of=${devB}`, "bs=1M", "count=32", "conv=fsync", "status=none"]);
    await must("mkfs.ext4", ["-q", devB]);
    const err = await failure(disk(devB, NAME_B, mntB).open(KEY));
    expect(err.message).toMatch(/^refusing to format .*: it holds data that is not a LUKS2 volume$/);
    expect(await blkidType(devB)).toBe("ext4");
    expect(await table(NAME_B)).toBeUndefined();
  });

  it("a header with the agent's parameters but a volume key the host chose opens, fails the table check and is closed", async () => {
    await must("wipefs", ["-a", devB]);
    // The strongest host: it even knows the keyslot passphrase. Only the volume key differs.
    const hostKey = new Uint8Array(64).fill(0x77);
    await must(
      "cryptsetup",
      ["luksFormat", "--type", "luks2", "--batch-mode", "--cipher", "aes-xts-plain64", "--key-size", "512", "--volume-key-file", "/dev/fd/3",
        "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--hash", "sha256", "--label", "sealed-data", "--key-file", "-", devB],
      { stdin: keys.passphrase, fds: [hostKey] },
    );
    // Same header shape as the agent's own, so only the table check can catch it.
    const meta: unknown = JSON.parse((await must("cryptsetup", ["luksDump", "--dump-json-metadata", devB])).stdout);
    expect(() => validateLuksHeader(meta)).not.toThrow();
    const err = await failure(disk(devB, NAME_B, mntB).open(KEY));
    expect(err).toBeInstanceOf(LuksHeaderError);
    expect(err.message).toMatch(/volume key is not the one derived from diskKey/);
    expect(await table(NAME_B)).toBeUndefined();
    // The control: opened by hand, the table carries exactly the host's key, so the comparison above was real.
    await openByHand(devB, NAME_B);
    expect(parseCryptTable((await table(NAME_B)) as string).key).toBe(hex(hostKey));
    await must("cryptsetup", ["close", NAME_B]);
  });

  it("a header with another cipher is refused before unlocking", async () => {
    await must("wipefs", ["-a", devB]);
    await must(
      "cryptsetup",
      ["luksFormat", "--type", "luks2", "--batch-mode", "--cipher", "aes-cbc-essiv:sha256", "--key-size", "256",
        "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--hash", "sha256", "--key-file", "-", devB],
      { stdin: keys.passphrase },
    );
    const err = await failure(disk(devB, NAME_B, mntB).open(KEY));
    expect(err).toBeInstanceOf(LuksHeaderError);
    expect(err.message).toMatch(/^untrusted LUKS2 header: keyslot key_size 32$/);
    expect(await table(NAME_B)).toBeUndefined();
  });
});

// Always runs: the CI job must test the userland the agent image ships, not whatever a runner has.
describe("agent-luks workflow", () => {
  it("runs the suite on the agent image's base with the agent image's Debian package pins", async () => {
    const dockerfile = await readFile(join(REPO, "runtime/agent/Dockerfile"), "utf8");
    const script = await readFile(join(REPO, "runtime/agent/test/luks-container.sh"), "utf8");
    const workflow = await readFile(join(REPO, ".github/workflows/agent-luks.yml"), "utf8");
    const image = /^ARG NODE_IMAGE=(\S+@sha256:[0-9a-f]{64})$/m.exec(dockerfile)?.[1];
    const snapshot = /^ARG DEBIAN_SNAPSHOT=(\S+)$/m.exec(dockerfile)?.[1];
    const runtimeStage = dockerfile.slice(dockerfile.indexOf("AS runtime"));
    const pins = [...runtimeStage.matchAll(/^[ \t]+([a-z0-9][a-z0-9.+-]*=[0-9][^\s\\]*)[ \t]*\\?$/gm)].map((m) => m[1]);
    expect(image).toBeDefined();
    expect(pins).toContain("cryptsetup-bin=2:2.6.1-4~deb12u2");
    expect(pins.length).toBeGreaterThanOrEqual(6);
    expect(workflow).toContain(`AGENT_BASE_IMAGE: ${image}`);
    expect(script).toContain(`snapshot=${snapshot}`);
    const scriptPins = [...script.matchAll(/^[ \t]+([a-z0-9][a-z0-9.+-]*=[0-9][^\s\\]*)[ \t]*\\?$/gm)].map((m) => m[1]);
    expect(scriptPins.sort()).toEqual(pins.sort());
    expect(script).toMatch(/^export SEALED_REAL_LUKS=1$/m);
    expect(script).toMatch(/^pnpm exec vitest run test\/disk\.real\.test\.ts$/m);
    expect(workflow).toMatch(/docker run --rm --privileged[\s\S]*"\$AGENT_BASE_IMAGE"[\s\S]*bash \/src\/runtime\/agent\/test\/luks-container\.sh/);
  });
});
