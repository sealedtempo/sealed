// A fake of the block-device tools sealed-agent's LuksDisk runs (cryptsetup, dmsetup, blkid, mkfs.ext4, mount),
// for a devnet on a laptop without dm-crypt. The "device" is a JSON state file standing in for the disk: the
// LUKS2 header (the keyslot passphrase digest and the volume key, as dm-crypt would derive them) and whether the
// filesystem was created survive agent restarts, exactly like the data disk survives a reboot. Mappings and mounts
// live in memory and in a mountinfo file that a new boot starts empty.
//
// It enforces what the real tools enforce for the agent's flow: open needs the passphrase the volume was
// formatted with (so a reboot only opens the disk if the broker released the same diskKey), the dm table shows the
// formatted volume key, and mounting needs an open mapping with a filesystem.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { CommandResult, CommandRunner } from "@sealed/agent/dist/src/disk.js";

interface DiskState {
  header?: { passphraseSha256: string; volumeKey: string; label: string; formattedAt: number };
  filesystem?: { label: string; createdAt: number };
  /** Every tool call (no key material), for the devnet's assertions. */
  ops: string[];
}

const ok = (stdout = ""): CommandResult => ({ code: 0, stdout, stderr: "" });
const fail = (code: number, stderr: string): CommandResult => ({ code, stdout: "", stderr });
const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

/** Escapes a path for /proc/self/mountinfo (space, tab, newline and backslash as octal). */
export function mountInfoEscape(p: string): string {
  return p.replace(/[ \t\n\\]/g, (c) => `\\${c.charCodeAt(0).toString(8).padStart(3, "0")}`);
}

/** LUKS2 metadata in the one layout LuksDisk accepts (validateLuksHeader). */
function luksMetadata(label: string) {
  return {
    keyslots: {
      "0": {
        type: "luks2",
        key_size: 64,
        af: { type: "luks1", stripes: 4000, hash: "sha256" },
        area: { type: "raw", offset: "32768", size: "258048", encryption: "aes-xts-plain64", key_size: 64 },
        kdf: { type: "pbkdf2", hash: "sha256", iterations: 1000, salt: "c2VhbGVkLWRldm5ldA==" },
      },
    },
    tokens: {},
    segments: { "0": { type: "crypt", offset: "16777216", size: "dynamic", iv_tweak: "0", encryption: "aes-xts-plain64", sector_size: 512 } },
    digests: { "0": { type: "pbkdf2", keyslots: ["0"], segments: ["0"], hash: "sha256", iterations: 1000, salt: "c2VhbGVk", digest: "ZGV2bmV0" } },
    config: { json_size: "12288", keyslots_size: "16744448", label },
  };
}

export interface FakeLuksOptions {
  /** The data disk's state file (persistent, like the disk). */
  statePath: string;
  /** The device path the agent is configured with. */
  device: string;
  /** This boot's mountinfo file (LuksDisk mountInfoPath). */
  mountInfoPath: string;
  /** major:minor reported for the device. */
  deviceId: string;
}

export class FakeLuksRunner implements CommandRunner {
  /** Open mappings of this boot: name -> device. */
  private readonly mappings = new Map<string, string>();

  private readonly o: FakeLuksOptions;

  constructor(o: FakeLuksOptions) {
    this.o = o;
    mkdirSync(dirname(o.mountInfoPath), { recursive: true });
    // A new boot: nothing is mapped or mounted yet.
    writeFileSync(o.mountInfoPath, "");
  }

  get state(): DiskState {
    if (!existsSync(this.o.statePath)) return { ops: [] };
    return JSON.parse(readFileSync(this.o.statePath, "utf8")) as DiskState;
  }

  private save(s: DiskState): void {
    mkdirSync(dirname(this.o.statePath), { recursive: true });
    writeFileSync(this.o.statePath, `${JSON.stringify(s, null, 2)}\n`, { mode: 0o600 });
  }

  private record(s: DiskState, op: string): void {
    s.ops.push(op);
    this.save(s);
  }

  async run(cmd: string, args: string[], opts?: { stdin?: Uint8Array; fds?: Uint8Array[] }): Promise<CommandResult> {
    const s = this.state;
    const last = args[args.length - 1] ?? "";
    const mapperOf = (name: string) => `/dev/mapper/${name}`;
    switch (`${cmd} ${args[0] ?? ""}`) {
      case "dmsetup table": {
        const name = last;
        const dev = this.mappings.get(name);
        if (!dev || !s.header) return fail(1, `Device ${name} does not exist.`);
        return ok(`0 2097152 crypt aes-xts-plain64 ${s.header.volumeKey} 0 ${this.o.deviceId} 32768\n`);
      }
      case "cryptsetup isLuks":
        return last === this.o.device && s.header ? ok() : fail(1, "not a LUKS device");
      case "blkid -p": {
        if (last === this.o.device) return s.header ? ok(`${last}: TYPE="crypto_LUKS"\n`) : fail(2, "");
        const name = [...this.mappings.keys()].find((n) => mapperOf(n) === last);
        if (name && s.filesystem) return ok(`${last}: LABEL="${s.filesystem.label}" TYPE="ext4"\n`);
        return fail(2, "");
      }
      case "cryptsetup luksFormat": {
        if (last !== this.o.device) return fail(4, `unknown device ${last}`);
        if (s.header) return fail(1, "device already holds a LUKS header");
        const pass = opts?.stdin;
        const volumeKey = opts?.fds?.[0];
        if (!pass || pass.length === 0 || !volumeKey || volumeKey.length !== 64) return fail(1, "passphrase on stdin and a 64-byte volume key on fd 3 are required");
        const label = args[args.indexOf("--label") + 1] ?? "";
        s.header = { passphraseSha256: sha256(pass), volumeKey: Buffer.from(volumeKey).toString("hex"), label, formattedAt: Date.now() };
        delete s.filesystem;
        this.record(s, "luksFormat");
        return ok();
      }
      case "cryptsetup luksDump":
        if (last !== this.o.device || !s.header) return fail(1, "not a LUKS device");
        return ok(JSON.stringify(luksMetadata(s.header.label)));
      case "cryptsetup open": {
        const name = last;
        const dev = args[args.length - 2] ?? "";
        if (dev !== this.o.device || !s.header) return fail(1, "not a LUKS device");
        const pass = opts?.stdin;
        if (!pass || sha256(pass) !== s.header.passphraseSha256) {
          this.record(s, "open:wrong-passphrase");
          return fail(2, "No key available with this passphrase.");
        }
        if (this.mappings.has(name)) return fail(5, `Device ${name} already exists.`);
        this.mappings.set(name, dev);
        this.record(s, "open");
        return ok();
      }
      case "cryptsetup close":
        this.mappings.delete(last);
        this.record(s, "close");
        return ok();
      case "mkfs.ext4 -q": {
        const name = [...this.mappings.keys()].find((n) => mapperOf(n) === last);
        if (!name) return fail(1, `${last}: no such device`);
        s.filesystem = { label: args[args.indexOf("-L") + 1] ?? "", createdAt: Date.now() };
        this.record(s, "mkfs.ext4");
        return ok();
      }
      case "mount -t": {
        const source = args[args.length - 2] ?? "";
        const target = last;
        const name = [...this.mappings.keys()].find((n) => mapperOf(n) === source);
        if (!name || !s.filesystem) return fail(32, `mount: ${target}: wrong fs type, bad option, bad superblock on ${source}`);
        mkdirSync(target, { recursive: true });
        const line = `36 25 ${this.o.deviceId} / ${mountInfoEscape(target)} rw,nosuid,nodev,relatime shared:1 - ext4 ${source} rw\n`;
        writeFileSync(this.o.mountInfoPath, readFileSync(this.o.mountInfoPath, "utf8") + line);
        this.record(s, "mount");
        return ok();
      }
    }
    return fail(127, `fake LUKS runner: unexpected command ${cmd} ${args.join(" ")}`);
  }
}
