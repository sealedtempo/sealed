// Boot step 4 and re-attestation (spec 5.6): an evidence bundle (sealed-evidence/v1) whose quote
// binds stackHash, configHash, enclaveSigner and a fresh nonce2, sent to the platform oracle.
import {
  type Address,
  bytesToHex,
  type EvidenceBundle,
  eventLogHash,
  evidenceReportData,
  type Hex,
  quoteHash,
  randomBytes,
} from "@sealed/core";
import type { Clock } from "./clock.js";
import type { DeploymentContext } from "./context.js";
import type { QuoteProvider } from "./dstack.js";
import { fetchJson } from "./http.js";
import type { Logger } from "./log.js";
import { withRetry } from "./retry.js";

export interface EvidenceResult {
  deploymentId: Hex;
  txHash?: Hex;
  kind?: "register" | "heartbeat";
}

export async function buildEvidence(
  ctx: DeploymentContext,
  dstack: QuoteProvider,
  enclaveSigner: Address,
  clock: Clock,
  runtime: "dstack" | "fallback" = "dstack",
): Promise<EvidenceBundle> {
  const nonce2 = randomBytes(32);
  const quote = await dstack.getQuote(evidenceReportData(ctx.stackHash, ctx.configHash, enclaveSigner, nonce2));
  const c = ctx.config.contracts;
  return {
    schema: "sealed-evidence/v1",
    chainId: ctx.config.chainId,
    contracts: {
      platformRegistry: c.platformRegistry.toLowerCase(),
      appRegistry: c.appRegistry.toLowerCase(),
      deploymentRegistry: c.deploymentRegistry.toLowerCase(),
    },
    deploymentId: ctx.deploymentId,
    customer: ctx.customer,
    imageId: ctx.imageId,
    releaseIds: ctx.releaseIds,
    config: ctx.configJson as EvidenceBundle["config"],
    configHash: ctx.configHash,
    appCompose: ctx.appCompose,
    stackHash: ctx.stackHash,
    enclaveSigner: enclaveSigner.toLowerCase(),
    nonce2: bytesToHex(nonce2),
    attestedAt: clock.now(),
    quote: bytesToHex(quote.quote),
    quoteHash: quoteHash(quote.quote),
    eventLog: quote.eventLog,
    eventLogHash: eventLogHash(quote.eventLog),
    runtime,
  };
}

export interface PlatformClient {
  postEvidence(bundle: EvidenceBundle): Promise<EvidenceResult>;
  postUsage(body: unknown): Promise<unknown>;
  postHealth(body: unknown): Promise<unknown>;
}

export class HttpPlatformClient implements PlatformClient {
  private readonly base: string;
  constructor(baseUrl: string) {
    this.base = baseUrl.replace(/\/$/, "");
  }
  postEvidence(bundle: EvidenceBundle) {
    return fetchJson<EvidenceResult>(`${this.base}/v1/evidence`, { body: bundle, timeoutMs: 120_000 });
  }
  postUsage(body: unknown) {
    return fetchJson(`${this.base}/v1/usage`, { body });
  }
  postHealth(body: unknown) {
    return fetchJson(`${this.base}/v1/health`, { body });
  }
}

/** Builds and submits evidence, retrying with backoff; a fresh quote for every attempt after a 4xx. */
export async function attestAndSubmit(
  ctx: DeploymentContext,
  dstack: QuoteProvider,
  platform: PlatformClient,
  enclaveSigner: Address,
  opts: { clock: Clock; log: Logger; signal?: AbortSignal; attempts?: number },
): Promise<EvidenceResult> {
  return withRetry(
    async () => {
      const bundle = await buildEvidence(ctx, dstack, enclaveSigner, opts.clock);
      const result = await platform.postEvidence(bundle);
      opts.log.info("evidence accepted", {
        deploymentId: ctx.deploymentId,
        quoteHash: bundle.quoteHash,
        attestedAt: bundle.attestedAt,
        kind: result?.kind,
        txHash: result?.txHash,
      });
      return result;
    },
    {
      attempts: opts.attempts ?? Number.POSITIVE_INFINITY,
      initialDelayMs: 2000,
      maxDelayMs: 300_000,
      signal: opts.signal,
      clock: opts.clock,
      log: opts.log,
      what: "evidence submission",
    },
  );
}
