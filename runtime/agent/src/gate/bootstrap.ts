// Whether each app's bootstrap job is done (brief items 9 and 10). sealed-stack/v1 names the done
// file on the data disk (`apps[].bootstrap.donePath`, `<volume>/<path>` under /mnt/sealed-data/<app>/);
// the gate keeps the app's routes at 503 `starting` until it exists as a regular file. The agent has
// no Docker socket, so it cannot see a bootstrap container exit; a job whose done file lives outside
// the data disk (donePath "") reports instead with `POST /v1/bootstrap/done` from its own fixed IP,
// and that report is kept in the agent's state on the encrypted disk. Done is final for the boot.
import { lstat } from "node:fs/promises";
import { join, normalize, relative } from "node:path";
import type { Logger } from "../log.js";
import { COMPOSE_DATA_ROOT, type StackInfo } from "../stack.js";

interface Watch {
  /** Local path of the done file, or undefined when the job reports itself. */
  path?: string;
  /** The bootstrap service's fixed IP (the only caller allowed to report). */
  ip?: string;
  done: boolean;
  checkedAt?: number;
  warned?: boolean;
}

export class BootstrapError extends Error {
  constructor(
    readonly status: 400 | 403 | 409,
    message: string,
  ) {
    super(message);
  }
}

export class BootstrapTracker {
  private readonly watches = new Map<string, Watch>();

  constructor(
    stack: StackInfo,
    dataMount: string,
    private readonly o: {
      log: Logger;
      /** Milliseconds. */
      now?: () => number;
      /** Apps whose job already reported done (persisted state). */
      reported?: readonly string[];
      /** Persists a new report. */
      onReported?: (app: string) => void;
      /** A missing done file is looked for again at most this often. */
      recheckMs?: number;
    },
  ) {
    const root = stack.dataRoot ?? COMPOSE_DATA_ROOT;
    for (const app of stack.apps) {
      const b = app.bootstrap;
      if (!b) continue;
      const ip = app.services.find((s) => s.name === b.service)?.ip;
      if (b.donePath === "") {
        this.watches.set(app.id, { ip, done: o.reported?.includes(app.id) ?? false });
        continue;
      }
      const rel = relative(normalize(root), normalize(b.donePath));
      if (!rel.startsWith(`${app.id}/`) || rel.split("/").includes("..")) {
        throw new Error(`sealed-stack: ${app.id} bootstrap done file ${b.donePath} is not under ${root}/${app.id}`);
      }
      this.watches.set(app.id, { path: join(dataMount, rel), ip, done: false });
    }
  }

  /** Apps that have a bootstrap job. */
  apps(): string[] {
    return [...this.watches.keys()];
  }

  async done(app: string): Promise<boolean> {
    const w = this.watches.get(app);
    if (!w) return true;
    if (w.done || !w.path) return w.done;
    const now = (this.o.now ?? Date.now)();
    if (w.checkedAt !== undefined && now - w.checkedAt < (this.o.recheckMs ?? 1000)) return false;
    w.checkedAt = now;
    try {
      const st = await lstat(w.path);
      if (st.isFile()) {
        w.done = true;
        this.o.log.info("app bootstrap done, its routes are open", { app });
        return true;
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ENOTDIR" && !w.warned) {
        w.warned = true;
        this.o.log.warn("cannot check the bootstrap done file; the app's routes stay closed", { app, code });
      }
    }
    return false;
  }

  /** POST /v1/bootstrap/done from the app's bootstrap service. */
  report(app: string, peer: string): void {
    const w = this.watches.get(app);
    if (!w) throw new BootstrapError(400, `${app} has no bootstrap job`);
    if (w.path) throw new BootstrapError(409, `${app} finishes its bootstrap with a done file on the data disk`);
    if (!w.ip || peer !== w.ip) throw new BootstrapError(403, `only ${app}'s bootstrap service may report it done`);
    if (w.done) return;
    w.done = true;
    this.o.onReported?.(app);
    this.o.log.info("app bootstrap reported done, its routes are open", { app });
  }
}
