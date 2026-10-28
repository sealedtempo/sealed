// GET /attest (spec 5.6 step 5): a fresh quote over sha256("sealed/attest/v1" || nonce ||
// tlsPubKeyHash || enclaveSigner), with everything a verifier needs to check it.
import { type Address, attestReportData, bytesToHex, type Hex, hexToBytes, isHexOfLength } from "@sealed/core";
import type { DeploymentContext } from "./context.js";
import type { QuoteProvider } from "./dstack.js";
import type { TlsKeySource } from "./tls.js";

export class AttestError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function liveAttestation(
  ctx: DeploymentContext,
  dstack: QuoteProvider,
  tls: TlsKeySource,
  enclaveSigner: Address,
  nonce: string,
) {
  if (!isHexOfLength(nonce, 32)) throw new AttestError(400, "nonce must be 0x-prefixed 32-byte hex");
  const tlsPubKeyHash = await tls.tlsPubKeyHash();
  if (!tlsPubKeyHash) throw new AttestError(503, "TLS certificate not issued yet");
  const reportData = attestReportData(hexToBytes(nonce), hexToBytes(tlsPubKeyHash), hexToBytes(enclaveSigner));
  const q = await dstack.getQuote(reportData);
  return {
    quote: bytesToHex(q.quote),
    eventLog: q.eventLog,
    config: ctx.configJson,
    releaseIds: ctx.releaseIds,
    appCompose: ctx.appCompose,
    enclaveSigner: enclaveSigner.toLowerCase() as Address,
    tlsPubKeyHash: tlsPubKeyHash.toLowerCase() as Hex,
    reportData: bytesToHex(reportData),
  };
}

/** Token bucket: quotes are expensive, and /attest is public. */
export class RateLimiter {
  private tokens: number;
  private last = Date.now();
  constructor(
    private readonly perSecond: number,
    private readonly burst: number,
  ) {
    this.tokens = burst;
  }
  take(): boolean {
    const now = Date.now();
    this.tokens = Math.min(this.burst, this.tokens + ((now - this.last) / 1000) * this.perSecond);
    this.last = now;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}

/** One token bucket per client address, bounded in memory (least recently used clients are dropped). */
export class ClientRateLimiter {
  private readonly buckets = new Map<string, RateLimiter>();
  constructor(
    private readonly perSecond: number,
    private readonly burst: number,
    private readonly maxClients = 4096,
  ) {}
  take(client: string): boolean {
    let b = this.buckets.get(client);
    if (b) this.buckets.delete(client);
    else {
      b = new RateLimiter(this.perSecond, this.burst);
      if (this.buckets.size >= this.maxClients) {
        const oldest = this.buckets.keys().next().value;
        if (oldest !== undefined) this.buckets.delete(oldest);
      }
    }
    this.buckets.set(client, b);
    return b.take();
  }
}
