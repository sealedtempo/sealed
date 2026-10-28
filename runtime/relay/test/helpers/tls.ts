import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, type Server } from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { AddressInfo } from 'node:net'

export type TlsFixture = { cert: string; key: string }

/** A fresh self-signed P-256 certificate for localhost (openssl CLI). */
export function selfSigned(): TlsFixture {
  const dir = mkdtempSync(join(tmpdir(), 'sealed-tls-'))
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-days', '2',
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    ], { stdio: 'ignore' })
    return { cert: readFileSync(join(dir, 'c.pem'), 'utf8'), key: readFileSync(join(dir, 'k.pem'), 'utf8') }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

export async function httpsServer(
  tls: TlsFixture,
  handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void,
): Promise<{ url: string; server: Server; close: () => Promise<void> }> {
  const server = createServer({ cert: tls.cert, key: tls.key }, handler)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()))
  const { port } = server.address() as AddressInfo
  return {
    url: `https://localhost:${port}`,
    server,
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(() => r()) }),
  }
}
