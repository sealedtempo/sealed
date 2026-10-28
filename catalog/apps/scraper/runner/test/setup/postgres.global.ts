import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { createServer, type AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import type { TestProject } from 'vitest/node';

// Starts one throwaway PostgreSQL cluster for the whole test run, on 127.0.0.1 and a random port,
// under the worktree's tmp/ (gitignored). Tests that need Postgres skip when the binaries are
// missing. Each test file creates its own database (see helpers/pg.ts).

declare module 'vitest' {
  export interface ProvidedContext {
    pgUrl: string;
  }
}

// Debian and Ubuntu (including GitHub runners) keep the server binaries off PATH.
function debianPgBins(): string[] {
  try {
    return readdirSync('/usr/lib/postgresql')
      .sort((a, b) => Number(b) - Number(a))
      .map((v) => `/usr/lib/postgresql/${v}/bin`);
  } catch {
    return [];
  }
}

function findPgBin(): string | null {
  const candidates = [process.env.PG_BIN, '/opt/homebrew/opt/postgresql@17/bin', ...debianPgBins()];
  for (const dir of candidates) if (dir && existsSync(join(dir, 'initdb'))) return dir;
  const which = spawnSync('which', ['initdb'], { encoding: 'utf8' });
  return which.status === 0 ? resolve(which.stdout.trim(), '..') : null;
}

async function freePort(): Promise<number> {
  const srv = createServer();
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address() as AddressInfo;
  await new Promise<void>((r) => srv.close(() => r()));
  return port;
}

async function waitReady(bin: string, port: number, child: ChildProcess): Promise<void> {
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(`postgres exited with code ${child.exitCode}`);
    const r = spawnSync(join(bin, 'pg_isready'), ['-h', '127.0.0.1', '-p', String(port), '-q']);
    if (r.status === 0) return;
    await new Promise((res) => setTimeout(res, 100));
  }
  throw new Error('postgres did not become ready');
}

export default async function setup(project: TestProject) {
  const bin = findPgBin();
  if (!bin || process.env.SCRAPER_SKIP_PG === '1') {
    project.provide('pgUrl', '');
    return;
  }
  const tmpRoot = process.env.SCRAPER_TEST_TMP ?? resolve(process.cwd(), '../../../../tmp');
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'scraper-pg-'));
  const data = join(dir, 'data');
  const init = spawnSync(
    join(bin, 'initdb'),
    ['-D', data, '-U', 'postgres', '-A', 'trust', '-E', 'UTF8', '--locale=C', '--no-sync'],
    { encoding: 'utf8', env: { ...process.env, LC_ALL: 'C' } },
  );
  if (init.status !== 0) throw new Error(`initdb failed: ${init.stderr}`);

  const port = await freePort();
  const child = spawn(
    join(bin, 'postgres'),
    ['-D', data, '-p', String(port), '-c', 'listen_addresses=127.0.0.1', '-c', 'unix_socket_directories=', '-c', 'fsync=off',
      '-c', 'synchronous_commit=off', '-c', 'full_page_writes=off'],
    // Without a valid LC_ALL, postgres on macOS refuses to start ("postmaster became multithreaded").
    { stdio: 'ignore', env: { ...process.env, LC_ALL: 'C' } },
  );
  try {
    await waitReady(bin, port, child);
  } catch (err) {
    child.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
    throw err;
  }
  project.provide('pgUrl', `postgres://postgres@127.0.0.1:${port}/postgres`);

  return async () => {
    const exited = new Promise<void>((r) => child.once('exit', () => r()));
    child.kill('SIGINT');
    await Promise.race([exited, new Promise((r) => setTimeout(r, 10_000))]);
    rmSync(dir, { recursive: true, force: true });
  };
}
