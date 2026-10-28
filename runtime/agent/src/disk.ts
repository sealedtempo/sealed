// The persistent data disk: LUKS2 with the broker-released diskKey, ext4, mounted at the data
// mount point (propagated to app containers). The key is passed on stdin, never in argv.
import { spawn } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import type { Logger } from "./log.js";

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface CommandRunner {
  run(cmd: string, args: string[], opts?: { stdin?: Uint8Array }): Promise<CommandResult>;
}

export const spawnRunner: CommandRunner = {
  run: (cmd, args, opts) =>
    new Promise((resolve, reject) => {
      const p = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      p.stdout.on("data", (d) => (stdout += String(d)));
      p.stderr.on("data", (d) => (stderr += String(d)));
      p.on("error", reject);
      p.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
      if (opts?.stdin) p.stdin.end(Buffer.from(opts.stdin));
      else p.stdin.end();
    }),
};

export interface DataDisk {
  /** Unlocks (or on first boot formats) and mounts the disk. Idempotent. */
  open(diskKey: Uint8Array): Promise<void>;
}

export interface LuksDiskOptions {
  device: string;
  name: string;
  mountPoint: string;
  runner?: CommandRunner;
  mountInfoPath?: string;
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

  private async ok(cmd: string, args: string[], stdin?: Uint8Array): Promise<CommandResult> {
    const r = await this.runner.run(cmd, args, stdin ? { stdin } : undefined);
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

  private async isMounted(): Promise<boolean> {
    const info = await readFile(this.opts.mountInfoPath ?? "/proc/self/mountinfo", "utf8").catch(() => "");
    return info.split("\n").some((line) => line.split(" ")[4] === this.opts.mountPoint);
  }

  async open(diskKey: Uint8Array): Promise<void> {
    if (diskKey.length !== 32) throw new Error("diskKey must be 32 bytes");
    const { device, name, mountPoint, log } = this.opts;
    if (await this.isMounted()) {
      log.info("data disk already mounted", { mountPoint });
      return;
    }
    const isLuks = (await this.runner.run("cryptsetup", ["isLuks", "--type", "luks2", device])).code === 0;
    let fresh = false;
    if (!isLuks) {
      if (await this.hasAnySignature(device)) {
        throw new Error(`refusing to format ${device}: it holds data that is not a LUKS2 volume`);
      }
      log.info("formatting new data disk with LUKS2", { device });
      // The key is 32 random bytes from the broker, so a slow PBKDF adds nothing; pbkdf2 with the
      // minimum iterations keeps memory use low inside the container.
      await this.ok(
        "cryptsetup",
        ["luksFormat", "--type", "luks2", "--batch-mode", "--cipher", "aes-xts-plain64", "--key-size", "512", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--label", "sealed-data", "--key-file", "-", device],
        diskKey,
      );
      fresh = true;
    }
    const mapped = (await this.runner.run("cryptsetup", ["status", name])).code === 0;
    if (!mapped) await this.ok("cryptsetup", ["open", "--type", "luks2", "--key-file", "-", device, name], diskKey);
    if (fresh || !(await this.hasAnySignature(this.mapper))) {
      log.info("creating ext4 filesystem on the data disk");
      await this.ok("mkfs.ext4", ["-q", "-L", "sealed-data", this.mapper]);
    }
    await mkdir(mountPoint, { recursive: true });
    await this.ok("mount", ["-t", "ext4", "-o", "nodev,nosuid", this.mapper, mountPoint]);
    log.info("data disk mounted", { mountPoint, formatted: fresh });
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
