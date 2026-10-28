import { X509Certificate, createHash } from 'node:crypto'
import { checkServerIdentity, type PeerCertificate } from 'node:tls'
import { Agent, type Dispatcher, ProxyAgent, fetch as undiciFetch } from 'undici'
import type { FetchLike } from './types.js'

/** sha256 of the DER SubjectPublicKeyInfo of a certificate, lowercase hex. */
export function spkiSha256Hex(certDer: Buffer | Uint8Array): string {
  const spki = new X509Certificate(Buffer.from(certDer)).publicKey.export({ type: 'spki', format: 'der' })
  return createHash('sha256').update(spki).digest('hex')
}

/** The HTTP CONNECT proxy for a URL from HTTPS_PROXY / NO_PROXY, as the in-VM egress setup sets them. */
export function proxyFor(url: URL, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const proxy = env.HTTPS_PROXY ?? env.https_proxy
  if (!proxy) return undefined
  const noProxy = (env.NO_PROXY ?? env.no_proxy ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
  const host = url.hostname.toLowerCase()
  for (const entry of noProxy) {
    if (entry === '*') return undefined
    const bare = entry.replace(/^\*?\./, '')
    if (host === bare || host.endsWith(`.${bare}`)) return undefined
  }
  return proxy
}

type TlsCheck = (host: string, cert: PeerCertificate) => Error | undefined

type TransportOptions = { proxy?: string; connections?: number; ca?: string | Buffer }

function dispatcherFor(origin: URL, check: TlsCheck, options: TransportOptions): Dispatcher {
  const tls = { checkServerIdentity: check, servername: origin.hostname, ...(options.ca ? { ca: options.ca } : {}) }
  const proxy = options.proxy ?? proxyFor(origin)
  if (proxy) return new ProxyAgent({ uri: proxy, requestTls: tls, connections: options.connections })
  return new Agent({ connect: tls, connections: options.connections })
}

function sameOriginOnly(origin: URL, fetchImpl: FetchLike): FetchLike {
  return (input, init) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, origin)
    if (url.protocol !== 'https:') return Promise.reject(new Error(`pinned transport refuses ${url.protocol} URLs`))
    if (url.origin !== origin.origin) return Promise.reject(new Error(`pinned transport refuses origin ${url.origin}`))
    return fetchImpl(url, init)
  }
}

/**
 * fetch bound to one HTTPS origin that accepts only peers whose SPKI sha256 is in `pins`,
 * after normal hostname and chain validation. Every new TLS connection is checked.
 */
export function createPinnedFetch(params: { baseURL: string; pins: readonly string[]; proxy?: string; ca?: string | Buffer }): {
  fetch: FetchLike
  close: () => Promise<void>
} {
  const origin = new URL(params.baseURL)
  const pins = new Set(params.pins.map((p) => p.toLowerCase()))
  if (pins.size === 0) throw new Error('createPinnedFetch needs at least one SPKI pin')
  const check: TlsCheck = (host, cert) => {
    const standard = checkServerIdentity(host, cert)
    if (standard) return standard
    if (!cert?.raw) return new Error('TLS pin check: peer certificate unavailable')
    const observed = spkiSha256Hex(cert.raw)
    if (!pins.has(observed)) return new Error(`TLS pin check: peer SPKI ${observed} is not attested`)
    return undefined
  }
  const dispatcher = dispatcherFor(origin, check, { proxy: params.proxy, ca: params.ca })
  const pinned: FetchLike = (input, init) =>
    undiciFetch(input as string, { ...(init as object), dispatcher } as never) as unknown as Promise<Response>
  return { fetch: sameOriginOnly(origin, pinned), close: () => dispatcher.close() }
}

/**
 * fetch over a single TLS connection that records the peer's SPKI hash, for flows that must
 * compare evidence with the key of the very connection that carried it.
 */
export function createCapturingFetch(params: { baseURL: string; proxy?: string; ca?: string | Buffer }): {
  fetch: FetchLike
  observedSpki: () => string | undefined
  close: () => Promise<void>
} {
  const origin = new URL(params.baseURL)
  let observed: string | undefined
  const check: TlsCheck = (host, cert) => {
    const standard = checkServerIdentity(host, cert)
    if (standard) return standard
    if (!cert?.raw) return new Error('TLS capture: peer certificate unavailable')
    const spki = spkiSha256Hex(cert.raw)
    if (observed && observed !== spki) return new Error('TLS capture: peer key changed between connections')
    observed = spki
    return undefined
  }
  const dispatcher = dispatcherFor(origin, check, { proxy: params.proxy, connections: 1, ca: params.ca })
  const capturing: FetchLike = (input, init) =>
    undiciFetch(input as string, { ...(init as object), dispatcher } as never) as unknown as Promise<Response>
  return { fetch: sameOriginOnly(origin, capturing), observedSpki: () => observed, close: () => dispatcher.close() }
}
