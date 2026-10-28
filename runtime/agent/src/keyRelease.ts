// Boot step 1-2 (spec 5.6): ephemeral X25519 key, broker nonce, quote over the kb-release
// report_data, POST /v1/release, HPKE-open the payload, derive the enclave signer.
import {
  type Address,
  bytesToHex,
  bytesToBareHex,
  deriveEnclavePrivateKey,
  enclaveSignerAddress,
  generateKeyPair,
  type Hex,
  hexToBytes,
  kbReleaseReportData,
  nonceResponseSchema,
  openKbRelease,
  parseCJSON,
  type ReleaseRequest,
  type ReleaseResponse,
  releasePlaintextSchema,
  releaseResponseSchema,
  sha256Hex,
} from "@sealed/core";
import type { Clock } from "./clock.js";
import type { DeploymentContext } from "./context.js";
import type { QuoteProvider } from "./dstack.js";
import { fetchJson, HttpError, isRetryable } from "./http.js";
import { errorFields, type Logger } from "./log.js";
import { withRetry } from "./retry.js";

export interface KeyBroker {
  nonce(): Promise<{ nonce: Hex; expiresAt: number }>;
  release(req: ReleaseRequest): Promise<ReleaseResponse>;
}

export class ReleaseDeniedError extends Error {
  constructor(
    readonly reason: string,
    readonly detail?: string,
  ) {
    super(`key broker denied release: ${reason}${detail ? ` (${detail})` : ""}`);
    this.name = "ReleaseDeniedError";
  }
}

export class HttpKeyBroker implements KeyBroker {
  constructor(private readonly baseUrl: string) {}

  async nonce() {
    return nonceResponseSchema.parse(await fetchJson(`${this.baseUrl.replace(/\/$/, "")}/v1/nonce`)) as { nonce: Hex; expiresAt: number };
  }

  async release(req: ReleaseRequest): Promise<ReleaseResponse> {
    try {
      return releaseResponseSchema.parse(await fetchJson(`${this.baseUrl.replace(/\/$/, "")}/v1/release`, { body: req, timeoutMs: 120_000 }));
    } catch (err) {
      if (err instanceof HttpError && err.status === 403) {
        const body = err.json() as { reason?: string; detail?: string } | undefined;
        throw new ReleaseDeniedError(body?.reason ?? "denied", body?.detail);
      }
      throw err;
    }
  }
}

export interface ReleasedKeys {
  /** app id (or "_gate") -> secret name -> value */
  secrets: Record<string, Record<string, string>>;
  diskKey: Uint8Array;
  enclaveKey: Hex;
  enclaveSigner: Address;
}

/** One attempt: a fresh nonce, quote and ephemeral key every time. */
export async function releaseOnce(ctx: DeploymentContext, dstack: QuoteProvider, broker: KeyBroker, log: Logger): Promise<ReleasedKeys> {
  const kp = await generateKeyPair();
  const { nonce } = await broker.nonce();
  const nonceBytes = hexToBytes(nonce, 32);
  const quote = await dstack.getQuote(kbReleaseReportData(nonceBytes, kp.publicKey));
  const composeEvent = quote.eventLog.find((e) => e.imr === 3 && e.event === "compose-hash");
  if (composeEvent && composeEvent.event_payload.toLowerCase() !== ctx.stackHash.slice(2)) {
    throw new Error("the booted compose-hash does not match app-compose.json");
  }
  const resp = await broker.release({
    nonce: bytesToHex(nonceBytes),
    ephemeralPub: bytesToHex(kp.publicKey),
    quote: bytesToHex(quote.quote),
    eventLog: quote.eventLog,
    config: ctx.configJson,
    appCompose: ctx.appCompose,
    releaseIds: ctx.releaseIds,
    imageId: ctx.imageId,
  });
  if (resp.stackHash.toLowerCase() !== ctx.stackHash) throw new Error("broker answered for a different stackHash");
  if (resp.deploymentId.toLowerCase() !== ctx.deploymentId) throw new Error("broker answered for a different deploymentId");
  const plaintext = await openKbRelease(kp.privateKey, nonceBytes, hexToBytes(resp.enc, 32), hexToBytes(resp.ciphertext));
  const payload = releasePlaintextSchema.parse(parseCJSON(new TextDecoder().decode(plaintext)));
  plaintext.fill(0);
  const enclaveKey = deriveEnclavePrivateKey(payload.signerSeed as Hex);
  const released: ReleasedKeys = {
    secrets: payload.secrets,
    diskKey: hexToBytes(payload.diskKey, 32),
    enclaveKey,
    enclaveSigner: enclaveSignerAddress(payload.signerSeed as Hex),
  };
  log.info("key release accepted", {
    stackHash: ctx.stackHash,
    deploymentId: ctx.deploymentId,
    quoteHash: sha256Hex(quote.quote),
    enclaveSigner: released.enclaveSigner,
    apps: Object.keys(payload.secrets).sort(),
    ephemeralPub: bytesToBareHex(kp.publicKey),
  });
  return released;
}

/**
 * Retries until the broker releases. Denials are retried slowly because the customer may still be
 * approving the stack; transport errors are retried quickly. Each attempt uses a fresh nonce.
 */
export async function releaseKeys(
  ctx: DeploymentContext,
  dstack: QuoteProvider,
  broker: KeyBroker,
  opts: { log: Logger; clock: Clock; signal?: AbortSignal; deniedDelayMs?: number; attempts?: number },
): Promise<ReleasedKeys> {
  return withRetry(
    async () => {
      try {
        return await releaseOnce(ctx, dstack, broker, opts.log);
      } catch (err) {
        if (err instanceof ReleaseDeniedError) {
          opts.log.warn("key release denied", { reason: err.reason, detail: err.detail, stackHash: ctx.stackHash });
          await opts.clock.sleep(opts.deniedDelayMs ?? 60_000, opts.signal);
        } else {
          opts.log.warn("key release attempt failed", errorFields(err));
        }
        throw err;
      }
    },
    {
      attempts: opts.attempts ?? Number.POSITIVE_INFINITY,
      initialDelayMs: 1000,
      maxDelayMs: 60_000,
      retryIf: (err) => err instanceof ReleaseDeniedError || isRetryable(err),
      signal: opts.signal,
      clock: opts.clock,
      what: "key release",
    },
  );
}
