// make devnet-e2e: the Sealed trust and payment flow end to end on this machine (see ../README.md).
//
//   node scripts/devnet/src/main.ts --bin <dir with sealed, key-broker, sealed-verifierd, sealed-compose> [--keep]
//
// Options: --api-dir <services/api of the private repo> (default: SEALED_API_DIR, then the sealed-platform checkout
// or the platform-integration worktree next to this repo), --pg-bin (PG_BIN, default
// /opt/homebrew/opt/postgresql@17/bin), --settle-seconds (default 4), --keep (keep the run directory and its logs
// after a pass; a failed run is always kept).
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Devnet } from "./flow.ts";
import { StepLog } from "./log.ts";
import { Supervisor } from "./procs.ts";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

function findApiDir(given?: string): string {
  const candidates = [given, process.env.SEALED_API_DIR, join(repo, "..", "sealed-platform", "services", "api"), join(repo, "..", "platform-integration", "services", "api")].filter(
    (p): p is string => !!p,
  );
  const found = candidates.find((p) => existsSync(join(p, "dist", "main.js")));
  if (!found) throw new Error(`no built platform api (dist/main.js) in ${candidates.join(", ")}; run scripts/devnet/run.sh or set SEALED_API_DIR`);
  return resolve(found);
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      bin: { type: "string" },
      "api-dir": { type: "string" },
      "pg-bin": { type: "string" },
      "settle-seconds": { type: "string", default: "4" },
      keep: { type: "boolean", default: false },
    },
  });
  const bin = resolve(values.bin ?? join(repo, "tmp", "devnet", "bin"));
  const bins = { sealed: join(bin, "sealed"), keyBroker: join(bin, "key-broker"), verifierd: join(bin, "sealed-verifierd"), compose: join(bin, "sealed-compose") };
  for (const [k, p] of Object.entries(bins)) if (!existsSync(p)) throw new Error(`missing ${k} binary ${p} (build with scripts/devnet/run.sh)`);
  const pgBin = values["pg-bin"] ?? process.env.PG_BIN ?? "/opt/homebrew/opt/postgresql@17/bin";
  if (!existsSync(join(pgBin, "initdb"))) throw new Error(`no PostgreSQL binaries in ${pgBin} (set PG_BIN)`);
  const runId = `${new Date().toISOString().replace(/[-:]/g, "").slice(0, 15)}-${randomBytes(3).toString("hex")}`;
  const runDir = join(repo, "tmp", "devnet", "runs", runId);
  mkdirSync(runDir, { recursive: true });
  const log = new StepLog();
  const sup = new Supervisor(join(runDir, "logs"));
  sup.installExitHandlers(() => process.stderr.write(`interrupted; run directory kept: ${runDir}\n`));
  const apiDir = findApiDir(values["api-dir"]);
  console.log(`devnet-e2e run ${runId}\n  repo    ${repo}\n  api     ${apiDir}\n  run dir ${runDir}\n  logs    ${join(runDir, "logs")}`);

  const devnet = new Devnet({ repo, apiDir, pgBin, bins, runDir, runId, sup, log, settleSeconds: Number(values["settle-seconds"]) });
  let failed: unknown;
  try {
    await devnet.run();
  } catch (err) {
    failed = err;
  }
  await sup.stopAll();
  await devnet.assets?.close().catch(() => undefined);
  await devnet.front?.close().catch(() => undefined);
  const lines = log.summary(failed ? "FAIL" : "PASS");
  if (failed) {
    lines.push("", `FAILED: ${failed instanceof Error ? failed.message : String(failed)}`, `run directory kept: ${runDir}`);
  }
  console.log(lines.join("\n"));
  writeFileSync(join(runDir, "summary.txt"), `${lines.join("\n")}\n`);
  if (!failed && !values.keep) {
    rmSync(runDir, { recursive: true, force: true });
    console.log(`removed ${runDir} (pass --keep to keep it)`);
  }
  return failed ? 1 : 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err instanceof Error ? (err.stack ?? err.message) : String(err));
    process.exit(1);
  },
);
