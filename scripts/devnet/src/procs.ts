// Process supervision for the devnet: every component runs as a child process with its output in its own log
// file. Children are stopped in reverse start order on success, on failure, on SIGINT/SIGTERM and (with SIGKILL)
// when the orchestrator exits for any other reason, so a run never leaves processes behind.
import { type ChildProcess, spawn } from "node:child_process";
import { closeSync, mkdirSync, openSync, readFileSync } from "node:fs";
import { join } from "node:path";

export interface SpawnOptions {
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  /** Replace the environment instead of extending process.env (clean-environment runs). */
  cleanEnv?: boolean;
}

export class Proc {
  readonly exited: Promise<number | null>;
  exitCode: number | null | undefined = undefined;

  readonly name: string;
  readonly child: ChildProcess;
  readonly logFile: string;

  constructor(name: string, child: ChildProcess, logFile: string) {
    this.name = name;
    this.child = child;
    this.logFile = logFile;
    this.exited = new Promise((resolve) => {
      child.once("exit", (code, signal) => {
        this.exitCode = code ?? (signal ? -1 : null);
        resolve(this.exitCode);
      });
      child.once("error", () => {
        this.exitCode = -1;
        resolve(-1);
      });
    });
  }

  get running(): boolean {
    return this.exitCode === undefined;
  }

  /** Last `lines` lines of the log file. */
  tail(lines = 40): string {
    try {
      return readFileSync(this.logFile, "utf8").trimEnd().split("\n").slice(-lines).join("\n");
    } catch {
      return "";
    }
  }

  log(): string {
    try {
      return readFileSync(this.logFile, "utf8");
    } catch {
      return "";
    }
  }

  /** SIGTERM, then SIGKILL after `graceMs`. */
  async stop(graceMs = 5000): Promise<void> {
    if (!this.running) return;
    this.child.kill("SIGTERM");
    const timer = setTimeout(() => this.child.kill("SIGKILL"), graceMs);
    await this.exited;
    clearTimeout(timer);
  }

  kill(): void {
    if (this.running) this.child.kill("SIGKILL");
  }
}

export class Supervisor {
  private readonly procs: Proc[] = [];
  private handlersInstalled = false;
  private seq = 0;

  readonly logDir: string;

  constructor(logDir: string) {
    this.logDir = logDir;
    mkdirSync(logDir, { recursive: true });
  }

  spawn(name: string, cmd: string, args: string[], o: SpawnOptions = {}): Proc {
    const file = join(this.logDir, `${String(++this.seq).padStart(2, "0")}-${name}.log`);
    const fd = openSync(file, "a");
    const env = o.cleanEnv ? (o.env ?? {}) : { ...process.env, ...o.env };
    const child = spawn(cmd, args, { cwd: o.cwd, env, stdio: ["ignore", fd, fd] });
    closeSync(fd);
    const p = new Proc(name, child, file);
    this.procs.push(p);
    return p;
  }

  /** Runs a command to completion; resolves with its exit code and log. */
  async run(name: string, cmd: string, args: string[], o: SpawnOptions = {}): Promise<{ code: number | null; output: string; logFile: string }> {
    const p = this.spawn(name, cmd, args, o);
    const code = await p.exited;
    this.procs.splice(this.procs.indexOf(p), 1);
    return { code, output: p.log(), logFile: p.logFile };
  }

  /** Runs a command that must exit 0; throws with the log tail otherwise. */
  async runOk(name: string, cmd: string, args: string[], o: SpawnOptions = {}): Promise<string> {
    const r = await this.run(name, cmd, args, o);
    if (r.code !== 0) throw new Error(`${name} failed (exit ${r.code}), log ${r.logFile}:\n${r.output.trimEnd().split("\n").slice(-40).join("\n")}`);
    return r.output;
  }

  running(): Proc[] {
    return this.procs.filter((p) => p.running);
  }

  async stopAll(): Promise<void> {
    for (const p of [...this.procs].reverse()) await p.stop();
  }

  killAll(): void {
    for (const p of this.procs) p.kill();
  }

  /** Stops children on SIGINT/SIGTERM and kills them if the process exits without cleanup. */
  installExitHandlers(onSignal?: () => void): void {
    if (this.handlersInstalled) return;
    this.handlersInstalled = true;
    process.on("exit", () => this.killAll());
    for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
      process.once(sig, () => {
        process.stderr.write(`\n${sig}: stopping devnet processes\n`);
        onSignal?.();
        void this.stopAll().finally(() => process.exit(130));
      });
    }
  }
}

export interface WaitOptions {
  timeoutMs?: number;
  intervalMs?: number;
  /** Fail at once (with its log tail) when this process exits. */
  proc?: Proc;
}

/** Polls `fn` until it returns a value other than undefined/false. */
export async function waitFor<T>(what: string, fn: () => Promise<T | undefined | false> | T | undefined | false, o: WaitOptions = {}): Promise<T> {
  const deadline = Date.now() + (o.timeoutMs ?? 30_000);
  let lastErr: unknown;
  for (;;) {
    try {
      const v = await fn();
      if (v !== undefined && v !== false) return v as T;
    } catch (err) {
      lastErr = err;
    }
    if (o.proc && !o.proc.running) {
      throw new Error(`${what}: ${o.proc.name} exited (code ${o.proc.exitCode}), log ${o.proc.logFile}:\n${o.proc.tail()}`);
    }
    if (Date.now() > deadline) {
      const tail = o.proc ? `\nlog ${o.proc.logFile}:\n${o.proc.tail()}` : "";
      throw new Error(`timed out waiting for ${what}${lastErr ? ` (last error: ${String(lastErr)})` : ""}${tail}`);
    }
    await sleep(o.intervalMs ?? 200);
  }
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
