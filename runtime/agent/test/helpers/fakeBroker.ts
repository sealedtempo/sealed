// A fake key broker implementing INTERFACES 9 over the simulator's quotes, using @sealed/core for
// report_data, RTMR3 replay and HPKE. It runs the checks that do not need a chain. The disk key and
// signer seed are derived as the real broker does (D-058, key-broker/kms.go KeyMessage):
// HMAC-SHA256(key, tag || customer (20 bytes) || salt (32 bytes)) with the v2 tags, so a stack upgrade
// that keeps the config salt keeps both.
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

/** The real broker's domain tags (key-broker/kms.go DiskKeyTag, SignerSeedTag; D-058 replaced the v1 deploymentId tags). */
export const DISK_KEY_TAG = "sealed/disk/v2";
export const SIGNER_SEED_TAG = "sealed/signer/v2";

export interface FakeBroker extends TestServer {
  releases: number;
  denials: string[];
  /** HMAC(key, tag || customer || salt), as key-broker DeriveKeys. */
  derive(tag: string, customer: Hex, salt: Hex): Hex;
  /** What every release carried, in order (the agent wipes its copy of the disk key after the unlock). */
  released: { stackHash: Hex; deploymentId: Hex; diskKey: Hex; signerSeed: Hex }[];
}

/** The MAC input of one derived key: tag || customer (20 bytes) || salt (32 bytes) (key-broker KeyMessage). */
export function keyMessage(tag: string, customer: Hex, salt: Hex): Buffer {
  const c = hexToBytes(customer);
  const s = hexToBytes(salt);
  if (c.length !== 20 || s.length !== 32) throw new Error("customer must be 20 bytes and salt 32 bytes");
  return Buffer.concat([Buffer.from(tag), Buffer.from(c), Buffer.from(s)]);
}

export async function startFakeBroker(opts: FakeBrokerOptions): Promise<FakeBroker> {
  const hmacKey = opts.hmacKey ?? randomBytes(32);
  const nonces = new Map<string, number>();
  const state = { releases: 0, denials: [] as string[], released: [] as FakeBroker["released"] };
  const derive = (tag: string, customer: Hex, salt: Hex): Hex =>
    bytesToHex(new Uint8Array(createHmac("sha256", hmacKey).update(keyMessage(tag, customer, salt)).digest()));
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
        // D-058: (customer, salt), not the deploymentId, so an upgraded stack keeps its disk and signer.
        const keys = { diskKey: derive(DISK_KEY_TAG, cfg.customer as Hex, cfg.salt), signerSeed: derive(SIGNER_SEED_TAG, cfg.customer as Hex, cfg.salt) };
        const plaintext = canonicalize({ secrets: opts.secrets, ...keys });
        const { enc, ciphertext } = await sealKbRelease(hexToBytes(r.ephemeralPub), hexToBytes(r.nonce), utf8(plaintext));
        state.releases++;
        state.released.push({ stackHash: stack, deploymentId: id, ...keys });
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
    get released() {
      return state.released;
    },
  };
}
