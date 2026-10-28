// Runs internal-tools-db's first-boot init script against a throwaway PostgreSQL cluster (the
// local PostgreSQL 16 or 17 binaries; skipped when none are installed) and checks the roles and
// database privileges ToolJet then works with.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import { unescapeFromCompose } from "../tools/embed-bootstrap.mjs";

const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const fragment = parse(readFileSync(join(appDir, "compose.fragment.yaml"), "utf8"));
const dbEntrypoint = unescapeFromCompose(fragment.services["internal-tools-db"].entrypoint[2]);

// The script the entrypoint writes to /docker-entrypoint-initdb.d.
export function initScript(entrypoint) {
  const lines = entrypoint.split("\n");
  const start = lines.findIndex((l) => /^cat > \/docker-entrypoint-initdb\.d\/\S+ <<'EOF'$/.test(l));
  const end = lines.findIndex((l, i) => i > start && l === "EOF");
  assert.ok(start >= 0 && end > start, "init script heredoc not found");
  return `${lines.slice(start + 1, end).join("\n")}\n`;
}

function pgBin() {
  for (const dir of ["/opt/homebrew/opt/postgresql@17/bin", "/opt/homebrew/opt/postgresql@16/bin", "/usr/lib/postgresql/17/bin", "/usr/lib/postgresql/16/bin"]) {
    if (existsSync(join(dir, "initdb"))) return dir;
  }
  const which = spawnSync("sh", ["-c", "command -v initdb"], { encoding: "utf8" });
  return which.status === 0 ? dirname(which.stdout.trim()) : undefined;
}

async function freePort() {
  const s = createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

const bin = pgBin();
describe("internal-tools-db init script on PostgreSQL", { skip: !bin && "no PostgreSQL binaries" }, () => {
  let dir;
  let env;
  const run = (cmd, args, extraEnv = {}) =>
    spawnSync(cmd.startsWith("/") ? cmd : join(bin, cmd), args, { encoding: "utf8", env: { ...env, ...extraEnv }, timeout: 60_000 });
  const psql = (user, db, sql) => run("psql", ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", db, "-c", sql]);

  before(async () => {
    // Throwaway cluster under the worktree's tmp/ (git-ignored), on a random local port.
    const tmpRoot = resolve(appDir, "../../../tmp");
    await mkdir(tmpRoot, { recursive: true });
    dir = await mkdtemp(join(tmpRoot, "pg-"));
    const port = await freePort();
    env = { PATH: `${bin}:${process.env.PATH}`, PGHOST: "127.0.0.1", PGPORT: String(port), LC_ALL: "C", LANG: "C" };
    const init = run("initdb", ["-D", join(dir, "data"), "-U", "postgres", "--auth=trust", "--no-sync", "-E", "UTF8", "--locale=C"]);
    assert.equal(init.status, 0, `${init.error ?? ""} ${init.stderr}`);
    const start = run("pg_ctl", ["-D", join(dir, "data"), "-l", join(dir, "log"), "-w", "-o", `-p ${port} -c listen_addresses=127.0.0.1 -c unix_socket_directories=`, "start"]);
    assert.equal(start.status, 0, start.stderr + start.stdout);
    const script = run("/bin/sh", ["-c", initScript(dbEntrypoint)], { POSTGRES_USER: "postgres", SAMPLE_DB_PASSWORD: "sample-pass" });
    assert.equal(script.status, 0, script.stderr);
  });

  after(async () => {
    if (!dir) return;
    run("pg_ctl", ["-D", join(dir, "data"), "-m", "immediate", "-w", "stop"]);
    await rm(dir, { recursive: true, force: true });
  });

  test("tooljet_sample is a login role that is not a superuser", () => {
    const res = psql("postgres", "postgres", "select rolcanlogin, rolsuper, rolcreatedb, rolcreaterole from pg_roles where rolname = 'tooljet_sample'");
    assert.equal(res.stdout.trim(), "t|f|t|f");
  });

  for (const db of ["tooljet_production", "tooljet_db"]) {
    test(`the sample role every workspace can use cannot connect to ${db}`, () => {
      const res = psql("tooljet_sample", db, "select 1");
      assert.notEqual(res.status, 0);
      assert.match(res.stderr, /permission denied for database "?\w+"?|does not have CONNECT privilege/);
      assert.equal(psql("postgres", db, "select 1").stdout.trim(), "1", "the ToolJet superuser still connects");
    });
  }

  test("ToolJet's createdb steps still work: existing databases are skipped, the sample db is created", () => {
    // create-database.ts runs createdb and ignores an error containing this text.
    const again = run("createdb", ["-U", "postgres", "tooljet_production"]);
    assert.notEqual(again.status, 0);
    assert.match(again.stderr, /database "tooljet_production" already exists/);
    const sample = run("createdb", ["-U", "tooljet_sample", "sample_db"]);
    assert.equal(sample.status, 0, sample.stderr);
    assert.equal(psql("tooljet_sample", "sample_db", "create table t (x int); select count(*) from t").stdout.trim(), "0");
  });

  test("PUBLIC keeps no CONNECT or TEMPORARY on the ToolJet databases", () => {
    const res = psql(
      "postgres",
      "postgres",
      "select datname, has_database_privilege('tooljet_sample', datname, 'CONNECT'), has_database_privilege('tooljet_sample', datname, 'TEMPORARY') from pg_database where datname in ('tooljet_production', 'tooljet_db') order by datname",
    );
    assert.equal(res.stdout.trim(), "tooljet_db|f|f\ntooljet_production|f|f");
  });
});
