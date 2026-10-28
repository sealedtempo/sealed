// The persistent data disk (D-017): LUKS2 keyed from the broker-released diskKey, ext4, mounted at the
// data mount point (propagated to app containers). The host attaches the disk, so nothing on it is
// trusted until checked:
// - The LUKS2 volume key is derived from diskKey (HKDF), not random, and after unlocking the agent
//   reads the live dm-crypt table and requires aes-xts-plain64 with exactly that key on the expected
//   backing device. A header the host crafted (cipher_null, a keyslot any passphrase opens, a volume
//   key it knows) can therefore never be mounted.
// - The header JSON is validated before unlocking (one aes-xts keyslot, one aes-xts segment, no
//   tokens, no integrity, no requirements), which also gives a clear error.
// - "Already mounted" means the topmost mount at the mount point is ext4 from /dev/mapper/<name>; the
//   composer's bind mount of the host directory at the same path does not count.
// Keys travel on stdin and fd 3, never in argv. Limit: aes-xts has no integrity, so the host can still
// corrupt blocks or roll the whole disk back to an older copy of itself.
import { spawn } from "node:child_process";
import { hkdfSync } from "node:crypto";
import { mkdir, readFile, stat } from "node:fs/promises";
import { normalize } from "node:path";
import type { Writable } from "node:stream";
import type { Logger } from "./log.js";

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface CommandRunner {
  /** `stdin` feeds fd 0; `fds[i]` feeds fd 3 + i through a pipe (read as /dev/fd/N). */
  run(cmd: string, args: string[], opts?: { stdin?: Uint8Array; fds?: Uint8Array[] }): Promise<CommandResult>;
}

export const spawnRunner: CommandRunner = {
  run: (cmd, args, opts) =>
    new Promise((resolve, reject) => {
      const extra = opts?.fds ?? [];
      const p = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe", ...extra.map(() => "pipe" as const)] });
      let stdout = "";
      let stderr = "";
      p.stdout?.on("data", (d) => (stdout += String(d)));
      p.stderr?.on("data", (d) => (stderr += String(d)));
      p.on("error", reject);
      p.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
      const feed = (w: Writable | null | undefined, data?: Uint8Array) => {
        if (!w) return;
        w.on("error", () => undefined); // the tool may exit without reading (EPIPE)
        w.end(data ? Buffer.from(data) : undefined);
      };
      feed(p.stdin, opts?.stdin);
      extra.forEach((d, i) => feed(p.stdio[3 + i] as Writable | null, d));
    }),
};

export interface DataDisk {
  /** Unlocks (or on first boot formats) and mounts the disk. Idempotent. */
  open(diskKey: Uint8Array): Promise<void>;
}

const LUKS_SALT = Buffer.from("sealed/disk/luks2/v1");
const CIPHER = "aes-xts-plain64";
const VOLUME_KEY_BYTES = 64;

/** passphrase (keyslot 0) and the LUKS2 volume key, both bound to diskKey. */
export function deriveLuksKeys(diskKey: Uint8Array): { passphrase: Uint8Array; volumeKey: Uint8Array } {
  if (diskKey.length !== 32) throw new Error("diskKey must be 32 bytes");
  return {
    passphrase: new Uint8Array(hkdfSync("sha256", diskKey, LUKS_SALT, "keyslot-passphrase", 32)),
    volumeKey: new Uint8Array(hkdfSync("sha256", diskKey, LUKS_SALT, "volume-key", VOLUME_KEY_BYTES)),
  };
}

export class LuksHeaderError extends Error {}

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

/** Checks `cryptsetup luksDump --dump-json-metadata` output against the only layout the agent creates. */
export function validateLuksHeader(meta: unknown): void {
  const fail = (msg: string): never => {
    throw new LuksHeaderError(`untrusted LUKS2 header: ${msg}`);
  };
  if (!isObj(meta)) fail("metadata is not an object");
  const m = meta as Json;
  const one = (section: string): Json => {
    const s = m[section];
    if (!isObj(s)) return fail(`no ${section}`);
    const keys = Object.keys(s);
    if (keys.length !== 1 || keys[0] !== "0" || !isObj(s["0"])) fail(`${section} must hold exactly entry "0", found [${keys.join(",")}]`);
    return s["0"] as Json;
  };
  const ks = one("keyslots");
  if (ks.type !== "luks2") fail(`keyslot type ${String(ks.type)}`);
  if (ks.key_size !== VOLUME_KEY_BYTES) fail(`keyslot key_size ${String(ks.key_size)}`);
  const area = isObj(ks.area) ? ks.area : fail("keyslot has no area");
  if (area.type !== "raw" || area.encryption !== CIPHER || area.key_size !== VOLUME_KEY_BYTES) {
    fail(`keyslot area ${String(area.type)}/${String(area.encryption)}/${String(area.key_size)}`);
  }
  const af = isObj(ks.af) ? ks.af : fail("keyslot has no af");
  if (af.type !== "luks1" || af.hash !== "sha256") fail(`keyslot af ${String(af.type)}/${String(af.hash)}`);
  const kdf = isObj(ks.kdf) ? ks.kdf : fail("keyslot has no kdf");
  if (kdf.type !== "pbkdf2" || kdf.hash !== "sha256") fail(`keyslot kdf ${String(kdf.type)}/${String(kdf.hash)}`);
  if ("priority" in ks && ks.priority !== 1) fail("keyslot priority");

  const seg = one("segments");
  if (seg.type !== "crypt" || seg.encryption !== CIPHER) fail(`segment ${String(seg.type)}/${String(seg.encryption)}`);
  if (seg.iv_tweak !== "0" || seg.size !== "dynamic") fail("segment iv_tweak/size");
  if (seg.sector_size !== 512 && seg.sector_size !== 4096) fail(`segment sector_size ${String(seg.sector_size)}`);
  if ("integrity" in seg || "flags" in seg) fail("segment integrity/flags");

  const dg = one("digests");
  if (dg.type !== "pbkdf2" || JSON.stringify(dg.keyslots) !== '["0"]' || JSON.stringify(dg.segments) !== '["0"]') fail("digest");

  if (!isObj(m.tokens) || Object.keys(m.tokens).length !== 0) fail("tokens are not allowed");
  const config = isObj(m.config) ? m.config : fail("no config");
  if ("requirements" in config) fail("requirements (for example online reencryption) are not allowed");
  if ("flags" in config && !(Array.isArray(config.flags) && config.flags.length === 0)) fail("persistent flags are not allowed");
}

export interface CryptTable {
  cipher: string;
  key: string;
  ivOffset: string;
  device: string;
  options: string[];
}

/** Parses `dmsetup table --showkeys <name>` for a single dm-crypt target. */
export function parseCryptTable(text: string): CryptTable {
  const lines = text.trim().split("\n").filter((l) => l.trim() !== "");
  if (lines.length !== 1) throw new LuksHeaderError(`expected one dm target, found ${lines.length}`);
  const f = (lines[0] as string).trim().split(/\s+/);
  if (f[2] !== "crypt" || f.length < 8) throw new LuksHeaderError(`dm target is ${f[2] ?? "missing"}, not crypt`);
  const optCount = f[8] !== undefined ? Number(f[8]) : 0;
  return { cipher: f[3] as string, key: f[4] as string, ivOffset: f[5] as string, device: f[6] as string, options: f.slice(9, 9 + optCount) };
}

export interface MountEntry {
  mountPoint: string;
  fstype: string;
  source: string;
}

const unescapeMount = (s: string) => s.replace(/\\([0-7]{3})/g, (_, o: string) => String.fromCharCode(Number.parseInt(o, 8)));

/** /proc/self/mountinfo: field 5 is the mount point; fstype and source follow the " - " separator. */
export function parseMountInfo(text: string): MountEntry[] {
  const out: MountEntry[] = [];
  for (const line of text.split("\n")) {
    const f = line.split(" ");
    const sep = f.indexOf("-", 6);
    if (f.length < 7 || sep < 0 || f[sep + 2] === undefined) continue;
    out.push({ mountPoint: unescapeMount(f[4] as string), fstype: f[sep + 1] as string, source: unescapeMount(f[sep + 2] as string) });
  }
  return out;
}

/** "major:minor" of a block device node (Linux dev_t encoding). */
export async function blockDeviceId(path: string): Promise<string> {
  const s = await stat(path, { bigint: true });
  if (!s.isBlockDevice()) throw new Error(`${path} is not a block device`);
  const dev = s.rdev;
  const major = ((dev >> 8n) & 0xfffn) | ((dev >> 32n) & ~0xfffn);
  const minor = (dev & 0xffn) | ((dev >> 12n) & ~0xffn);
  return `${major}:${minor}`;
}

export interface LuksDiskOptions {
  device: string;
  name: string;
  mountPoint: string;
  runner?: CommandRunner;
  mountInfoPath?: string;
  deviceId?: (path: string) => Promise<string>;
  log: Logger;
}

export class LuksDisk implements DataDisk {
  private readonly runner: CommandRunner;
  constructor(private readonly opts: LuksDiskOptions) {
    this.runner = opts.runner ?? spawnRunner;
  }

  private get mapper() {
    return `/dev/mapper/${this.opts.name}`;
  }

  /** Runs a command that must succeed. Only stderr goes into errors: stdout may carry key material. */
  private async ok(cmd: string, args: string[], opts?: { stdin?: Uint8Array; fds?: Uint8Array[] }): Promise<CommandResult> {
    const r = await this.runner.run(cmd, args, opts);
    if (r.code !== 0) throw new Error(`${cmd} ${args[0] ?? ""} failed (${r.code}): ${r.stderr.trim().slice(0, 300)}`);
    return r;
  }

  /** blkid -p exits 2 when it finds no signature at all, which is the only state we format. */
  private async hasAnySignature(dev: string): Promise<boolean> {
    const r = await this.runner.run("blkid", ["-p", dev]);
    if (r.code === 2) return false;
    if (r.code === 0) return true;
    throw new Error(`blkid failed on ${dev} (${r.code}): ${r.stderr.trim().slice(0, 300)}`);
  }

  private async topMount(): Promise<MountEntry | undefined> {
    const info = await readFile(this.opts.mountInfoPath ?? "/proc/self/mountinfo", "utf8").catch(() => "");
    const target = normalize(this.opts.mountPoint);
    return parseMountInfo(info)
      .filter((e) => normalize(e.mountPoint) === target)
      .at(-1);
  }

  private isOurMount(e: MountEntry | undefined): boolean {
    return e !== undefined && e.fstype === "ext4" && e.source === this.mapper;
  }

  /** The live dm table, or undefined when the mapping does not exist. */
  private async liveTable(): Promise<CryptTable | undefined> {
    const r = await this.runner.run("dmsetup", ["table", "--showkeys", this.opts.name]);
    if (r.code !== 0) return undefined;
    return parseCryptTable(r.stdout);
  }

  private checkTable(t: CryptTable, volumeKey: Uint8Array, deviceId: string): void {
    if (t.cipher !== CIPHER) throw new LuksHeaderError(`dm-crypt cipher is ${t.cipher}, expected ${CIPHER}`);
    if (t.key.startsWith(":")) throw new LuksHeaderError("dm-crypt key is in the kernel keyring; the mapping was not opened by this agent");
    if (t.key.toLowerCase() !== Buffer.from(volumeKey).toString("hex")) throw new LuksHeaderError("dm-crypt volume key is not the one derived from diskKey");
    if (t.ivOffset !== "0") throw new LuksHeaderError("dm-crypt iv offset");
    if (t.device !== deviceId) throw new LuksHeaderError(`dm-crypt backing device ${t.device} is not ${this.opts.device} (${deviceId})`);
    if (t.options.some((o) => o.startsWith("integrity"))) throw new LuksHeaderError("dm-crypt integrity options");
  }

  private async readHeader(): Promise<void> {
    const r = await this.ok("cryptsetup", ["luksDump", "--dump-json-metadata", this.opts.device]);
    let meta: unknown;
    try {
      meta = JSON.parse(r.stdout);
    } catch {
      throw new LuksHeaderError("untrusted LUKS2 header: metadata is not JSON");
    }
    validateLuksHeader(meta);
  }

  async open(diskKey: Uint8Array): Promise<void> {
    const { device, name, mountPoint, log } = this.opts;
    const keys = deriveLuksKeys(diskKey);
    try {
      const deviceId = await (this.opts.deviceId ?? blockDeviceId)(device);
      let fresh = false;
      let table = await this.liveTable();
      if (table) {
        // The agent restarted inside the same boot: the mapping must still be exactly ours.
        this.checkTable(table, keys.volumeKey, deviceId);
      } else {
        const isLuks = (await this.runner.run("cryptsetup", ["isLuks", "--type", "luks2", device])).code === 0;
        if (!isLuks) {
          if (await this.hasAnySignature(device)) throw new Error(`refusing to format ${device}: it holds data that is not a LUKS2 volume`);
          log.info("formatting new data disk with LUKS2", { device });
          // Both keys are 32+ bytes of HKDF output, so a slow PBKDF adds nothing; pbkdf2 with the
          // minimum iterations keeps memory use low inside the container.
          await this.ok(
            "cryptsetup",
            ["luksFormat", "--type", "luks2", "--batch-mode", "--cipher", CIPHER, "--key-size", "512", "--volume-key-file", "/dev/fd/3",
              "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--hash", "sha256", "--label", "sealed-data", "--key-file", "-", device],
            { stdin: keys.passphrase, fds: [keys.volumeKey] },
          );
          fresh = true;
        }
        await this.readHeader();
        await this.ok("cryptsetup", ["open", "--type", "luks2", "--disable-keyring", "--key-file", "-", device, name], { stdin: keys.passphrase });
        table = await this.liveTable();
        try {
          if (!table) throw new LuksHeaderError("dm-crypt mapping missing after open");
          this.checkTable(table, keys.volumeKey, deviceId);
        } catch (err) {
          await this.runner.run("cryptsetup", ["close", name]);
          throw err;
        }
      }
      if (this.isOurMount(await this.topMount())) {
        log.info("data disk already mounted", { mountPoint });
        return;
      }
      if (fresh) {
        log.info("creating ext4 filesystem on the data disk");
        await this.ok("mkfs.ext4", ["-q", "-L", "sealed-data", this.mapper]);
      } else if (!(await this.hasAnySignature(this.mapper))) {
        // An established volume whose plaintext shows no filesystem: corrupted ciphertext (or a first boot that
        // stopped between luksFormat and mkfs). Formatting would turn a fault into the loss of the customer's
        // data, so the boot stops and the volume stays as it is (review ws-int-agent 10).
        await this.runner.run("cryptsetup", ["close", name]);
        throw new Error(`refusing to format ${device}: the existing LUKS2 volume holds no filesystem; it is left untouched`);
      }
      await mkdir(mountPoint, { recursive: true });
      await this.ok("mount", ["-t", "ext4", "-o", "nodev,nosuid", this.mapper, mountPoint]);
      if (!this.isOurMount(await this.topMount())) throw new Error(`${mountPoint} does not show the encrypted filesystem after mount`);
      log.info("data disk mounted", { mountPoint, formatted: fresh });
    } finally {
      keys.passphrase.fill(0);
      keys.volumeKey.fill(0);
    }
  }
}

/** Development and tests: a plain directory instead of an encrypted disk. */
export class DirDisk implements DataDisk {
  constructor(private readonly mountPoint: string) {}
  async open(diskKey: Uint8Array): Promise<void> {
    if (diskKey.length !== 32) throw new Error("diskKey must be 32 bytes");
    await mkdir(this.mountPoint, { recursive: true, mode: 0o700 });
  }
}
