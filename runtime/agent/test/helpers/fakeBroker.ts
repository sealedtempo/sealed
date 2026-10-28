// A fake key broker implementing INTERFACES 9 over the simulator's quotes, using @sealed/core for
// report_data, RTMR3 replay and HPKE. It runs the checks that do not need a chain.
import { createHmac, randomBytes } from "node:crypto";
import {
  bytesToHex,
  canonicalize,
  configHash,
  decodeSimQuote,
  deploymentId as computeDeploymentId,
  type DstackEvent,
  equalBytes,
  type Hex,
  hexToBytes,
  isSimQuote,
  kbReleaseReportData,
  replayRtmr3,
  sealKbRelease,
  stackHash as computeStackHash,
  utf8,
  verifySealedEventLog,
} from "@sealed/core";
import { serve, type TestServer } from "./http.js";

export interface FakeBrokerOptions {
  customer: string;
  secrets: Record<string, Record<string, string>>;
  /** Deny with stack_not_approved until this returns true. */
  approved?: () => boolean;
  hmacKey?: Buffer;
}

export interface FakeBroker extends TestServer {
  releases: number;
  denials: string[];
  derive(tag: string, deploymentId: Hex): Hex;
}

export async function startFakeBroker(opts: FakeBrokerOptions): Promise<FakeBroker> {
  const hmacKey = opts.hmacKey ?? randomBytes(32);
  const nonces = new Map<string, number>();
  const state = { releases: 0, denials: [] as string[] };
  const derive = (tag: string, id: Hex): Hex =>
    bytesToHex(new Uint8Array(createHmac("sha256", hmacKey).update(Buffer.concat([Buffer.from(tag), Buffer.from(hexToBytes(id))])).digest()));
  const deny = (reason: string, detail = "") => {
    state.denials.push(reason);
    return { status: 403, body: { decision: "denied", reason, detail } };
  };
  const server = await serve((req, body) => {
    if (req.method === "GET" && req.url === "/v1/nonce") {
      const nonce = bytesToHex(new Uint8Array(randomBytes(32)));
      const expiresAt = Math.floor(Date.now() / 1000) + 300;
      nonces.set(nonce, expiresAt);
      return { status: 200, body: { nonce, expiresAt } };
    }
    if (req.method === "POST" && req.url === "/v1/release") {
      return (async () => {
        const r = JSON.parse(body) as {
          nonce: Hex; ephemeralPub: Hex; quote: Hex; eventLog: DstackEvent[]; config: Record<string, unknown>;
          appCompose: string; releaseIds: Hex[]; imageId: Hex;
        };
        const exp = nonces.get(r.nonce);
        nonces.delete(r.nonce);
        if (!exp || exp < Date.now() / 1000) return deny("bad_nonce");
        const quote = hexToBytes(r.quote);
        if (!isSimQuote(quote)) return deny("quote_invalid");
        const q = decodeSimQuote(quote);
        const expected = kbReleaseReportData(hexToBytes(r.nonce), hexToBytes(r.ephemeralPub));
        if (!equalBytes(hexToBytes(q.reportData), expected)) return deny("report_data_mismatch");
        if (q.debug) return deny("image_debug");
        let rtmr3: Uint8Array;
        try {
          rtmr3 = verifySealedEventLog(r.eventLog, r.appCompose);
        } catch (err) {
          return deny("rtmr3_replay", (err as Error).message);
        }
        if (!equalBytes(rtmr3, hexToBytes(q.rtmr3)) || !equalBytes(replayRtmr3(r.eventLog), rtmr3)) return deny("rtmr3_replay");
        const cfg = r.config as { customer: string; salt: Hex; imageId: Hex; apps: { releaseId: Hex }[] };
        if (cfg.customer.toLowerCase() !== opts.customer.toLowerCase()) return deny("customer_mismatch");
        if (JSON.stringify(cfg.apps.map((a) => a.releaseId)) !== JSON.stringify(r.releaseIds) || cfg.imageId !== r.imageId) {
          return deny("stack_not_approved", "release set");
        }
        if (opts.approved && !opts.approved()) return deny("stack_not_approved");
        void configHash(r.config);
        const stack = computeStackHash(r.appCompose);
        const id = computeDeploymentId(cfg.customer as Hex, stack, cfg.salt);
        const plaintext = canonicalize({
          secrets: opts.secrets,
          diskKey: derive("sealed/disk/v1", id),
          signerSeed: derive("sealed/signer/v1", id),
        });
        const { enc, ciphertext } = await sealKbRelease(hexToBytes(r.ephemeralPub), hexToBytes(r.nonce), utf8(plaintext));
        state.releases++;
        return { status: 200, body: { stackHash: stack, deploymentId: id, enc: bytesToHex(enc), ciphertext: bytesToHex(ciphertext) } };
      })();
    }
    return { status: 404, body: { error: "not found" } };
  });
  return {
    ...server,
    derive,
    get releases() {
      return state.releases;
    },
    get denials() {
      return state.denials;
    },
  };
}
