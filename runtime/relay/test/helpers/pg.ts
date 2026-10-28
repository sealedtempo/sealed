import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { join, resolve } from 'node:path'

const PG_BIN = process.env.PG_BIN ?? '/opt/homebrew/opt/postgresql@17/bin'

export function postgresAvailable(): boolean {
  return existsSync(join(PG_BIN, 'initdb')) && existsSync(join(PG_BIN, 'pg_ctl'))
}

async function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer()
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      server.close(() => (typeof address === 'object' && address ? resolvePort(address.port) : reject(new Error('no port'))))
    })
  })
}

export type Cluster = { url: string; stop: () => void }

/** A throwaway PostgreSQL 17 cluster under the worktree's tmp/, TCP on a random port, no unix socket. */
export async function startCluster(): Promise<Cluster> {
  const root = resolve(import.meta.dirname, '../../../../tmp')
  mkdirSync(root, { recursive: true })
  const dir = join(root, `pg-relay-${process.pid}-${Date.now()}`)
  const port = await freePort()
  const env = { ...process.env, LC_ALL: 'C', LANG: 'C' }
  execFileSync(join(PG_BIN, 'initdb'), ['-D', dir, '-U', 'postgres', '--auth=trust', '-E', 'UTF8', '--no-locale'], { stdio: 'ignore', env })
  const start = spawnSync(
    join(PG_BIN, 'pg_ctl'),
    ['-D', dir, '-l', join(dir, 'server.log'), '-w', '-o', `-p ${port} -c listen_addresses=127.0.0.1 -c unix_socket_directories=''`, 'start'],
    { stdio: 'ignore', env },
  )
  if (start.status !== 0) {
    rmSync(dir, { recursive: true, force: true })
    throw new Error('pg_ctl start failed')
  }
  execFileSync(join(PG_BIN, 'createdb'), ['-h', '127.0.0.1', '-p', String(port), '-U', 'postgres', 'relay'], { stdio: 'ignore', env })
  return {
    url: `postgresql://postgres@127.0.0.1:${port}/relay`,
    stop: () => {
      spawnSync(join(PG_BIN, 'pg_ctl'), ['-D', dir, '-m', 'fast', '-w', 'stop'], { stdio: 'ignore', env })
      rmSync(dir, { recursive: true, force: true })
    },
  }
}
