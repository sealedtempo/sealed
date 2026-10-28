import { X509Certificate, createHash } from 'node:crypto'
import { checkServerIdentity, type PeerCertificate } from 'node:tls'
import { Agent, type Dispatcher, ProxyAgent, fetch as undiciFetch } from 'undici'

/** sha256 of the DER SubjectPublicKeyInfo, 0x-prefixed lowercase hex (INTERFACES section 3 tlsPubKeyHash). */
export function tlsPubKeyHash(certDer: Buffer | Uint8Array): `0x${string}` {
  const spki = new X509Certificate(Buffer.from(certDer)).publicKey.export({ type: 'spki', format: 'der' })
  return `0x${createHash('sha256').update(spki).digest('hex')}`
}

export function proxyFor(url: URL, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const proxy = env.HTTPS_PROXY ?? env.https_proxy
  if (!proxy) return undefined
  const noProxy = (env.NO_PROXY ?? env.no_proxy ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
  const host = url.hostname.toLowerCase()
  for (const entry of noProxy) {
    if (entry === '*') return undefined
    const bare = entry.replace(/^\*?\./, '')
    if (host === bare || host.endsWith(`.${bare}`)) return undefined
  }
  return proxy
}

export type CapturedResponse = { response: Response; tlsPubKeyHash: `0x${string}` }

/**
 * GET over one fresh TLS connection (through the egress CONNECT proxy when configured),
 * returning the response together with the hash of the key the peer presented on it.
 */
export async function fetchWithPeerKey(url: string, options: { ca?: string | Buffer; timeoutMs?: number } = {}): Promise<CapturedResponse> {
  const target = new URL(url)
  if (target.protocol !== 'https:') throw new Error('attestation must be fetched over https')
  let observed: `0x${string}` | undefined
  const check = (host: string, cert: PeerCertificate): Error | undefined => {
    const standard = checkServerIdentity(host, cert)
    if (standard) return standard
    if (!cert?.raw) return new Error('peer certificate unavailable')
    observed = tlsPubKeyHash(cert.raw)
    return undefined
  }
  const tls = { checkServerIdentity: check, servername: target.hostname, ...(options.ca ? { ca: options.ca } : {}) }
  const proxy = proxyFor(target)
  const dispatcher: Dispatcher = proxy
    ? new ProxyAgent({ uri: proxy, requestTls: tls, connections: 1 })
    : new Agent({ connect: tls, connections: 1 })
  try {
    const res = (await undiciFetch(url, {
      dispatcher,
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(options.timeoutMs ?? 20_000),
    } as never)) as unknown as Response
    const body = await res.arrayBuffer()
    if (!observed) throw new Error('no TLS peer key observed')
    return { response: new Response(body, { status: res.status, headers: res.headers }), tlsPubKeyHash: observed }
  } finally {
    await dispatcher.close().catch(() => {})
  }
}
