// bcrypt ($2a$, $2b$, $2y$) for the password gate (D-044). The released gate secret is a bcrypt hash
// (`_gate/GATE_PASSWORD_BCRYPT`, INTERFACES 9), which Caddy's basic_auth used to check; the agent now
// checks it for Caddy's forward_auth. EksBlowfish as in OpenBSD's bcrypt.c and Go's
// golang.org/x/crypto/bcrypt; the tests compare it with Go's implementation.
//
// Self-contained on purpose (node builtins only, erasable TypeScript): the same file is the worker
// entry that keeps the expensive key schedule off the agent's event loop, and it runs unchanged from
// dist/ and, under Node's type stripping, from the sources in tests. The Blowfish P-array and S-boxes
// are the fractional hexadecimal digits of pi; they are derived here once per process (about 0.1 s)
// and checked against published words, instead of being pasted as 1042 literals.
import { timingSafeEqual } from "node:crypto";
import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";

const ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const INDEX = new Map([...ALPHABET].map((c, i) => [c, i]));
/** "OrpheanBeholderScryDoubt" */
const MAGIC = Uint32Array.of(0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274);
export const BCRYPT_MAX_PASSWORD_BYTES = 72;
/** Costs above this would let one login take minutes; such a hash is treated as unusable. */
export const BCRYPT_MAX_COST = 20;

/** The first `digits` fractional hexadecimal digits of pi (Machin's formula, fixed point, 64 guard bits). */
export function piHex(digits: number): string {
  const guard = 64n;
  const one = 1n << (BigInt(digits) * 4n + guard);
  const arctanInv = (x: bigint): bigint => {
    const x2 = x * x;
    let term = one / x;
    let sum = term;
    for (let k = 1n; term !== 0n; k++) {
      term /= x2;
      const t = term / (2n * k + 1n);
      sum = k % 2n === 1n ? sum - t : sum + t;
    }
    return sum;
  };
  const pi = 16n * arctanInv(5n) - 4n * arctanInv(239n);
  return ((pi - 3n * one) >> guard).toString(16).padStart(digits, "0");
}

let initial: { p: Int32Array; s: Int32Array } | undefined;

/** P (18 words) and S (4 x 256 words) as published with Blowfish, spot-checked. */
function initialState(): { p: Int32Array; s: Int32Array } {
  if (initial) return initial;
  const hex = piHex(1042 * 8);
  const words = new Int32Array(1042);
  for (let i = 0; i < 1042; i++) words[i] = Number.parseInt(hex.slice(8 * i, 8 * i + 8), 16) | 0;
  const known: [number, number][] = [
    [0, 0x243f6a88],
    [1, 0x85a308d3],
    [17, 0x8979fb1b],
    [18, 0xd1310ba6],
    [18 + 256, 0x4b7a70e9],
    [18 + 512, 0xe93d5a68],
    [18 + 768, 0x3a39ce37],
    [18 + 1023, 0x3ac372e6],
  ];
  for (const [i, w] of known) if (words[i] !== (w | 0)) throw new Error("blowfish constants are wrong");
  initial = { p: words.slice(0, 18), s: words.slice(18) };
  return initial;
}

function encode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += ALPHABET[b0 >> 2];
    out += ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    if (b1 === undefined) break;
    out += ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    if (b2 === undefined) break;
    out += ALPHABET[b2 & 0x3f];
  }
  return out;
}

function decode(text: string, length: number): Uint8Array | undefined {
  const out = new Uint8Array(length);
  let bits = 0;
  let acc = 0;
  let n = 0;
  for (const c of text) {
    const v = INDEX.get(c);
    if (v === undefined) return undefined;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (n < length) out[n++] = (acc >> bits) & 0xff;
    }
  }
  return n === length ? out : undefined;
}

export interface ParsedBcrypt {
  minor: "a" | "b" | "y";
  cost: number;
  /** The 22 salt characters as stored. */
  saltText: string;
  salt: Uint8Array;
  /** The 31 digest characters as stored. */
  digest: string;
}

/** Parses `$2<a|b|y>$<cost>$<22 salt chars><31 digest chars>`; undefined when it is not one. */
export function parseBcrypt(hash: string): ParsedBcrypt | undefined {
  const m = /^\$2([aby])\$(\d\d)\$([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})$/.exec(hash.trim());
  if (!m) return undefined;
  const cost = Number(m[2]);
  if (cost < 4 || cost > 31) return undefined;
  const salt = decode(m[3] as string, 16);
  if (!salt) return undefined;
  return { minor: m[1] as ParsedBcrypt["minor"], cost, saltText: m[3] as string, salt, digest: m[4] as string };
}

/** The bcrypt digest (23 bytes, encoded) of a password (at most 72 bytes are used) for a salt and cost. */
export function bcryptDigest(password: Uint8Array, salt: Uint8Array, cost: number): string {
  if (salt.length !== 16) throw new Error("bcrypt salt must be 16 bytes");
  if (!Number.isInteger(cost) || cost < 4 || cost > 31) throw new Error("bcrypt cost must be 4..31");
  const init = initialState();
  const P = Int32Array.from(init.p);
  const S = Int32Array.from(init.s);
  // The key is the password with its terminating NUL, used cyclically; only 72 bytes are ever read.
  const key = new Uint8Array(Math.min(password.length, BCRYPT_MAX_PASSWORD_BYTES) + 1);
  key.set(password.subarray(0, BCRYPT_MAX_PASSWORD_BYTES));
  const lr = new Int32Array(2);

  const encipher = (block: Int32Array, off: number) => {
    let l = (block[off] as number) ^ (P[0] as number);
    let r = block[off + 1] as number;
    for (let i = 1; i <= 16; i += 2) {
      r ^= ((((S[l >>> 24] as number) + (S[0x100 | ((l >>> 16) & 0xff)] as number)) ^ (S[0x200 | ((l >>> 8) & 0xff)] as number)) + (S[0x300 | (l & 0xff)] as number)) ^ (P[i] as number);
      l ^= ((((S[r >>> 24] as number) + (S[0x100 | ((r >>> 16) & 0xff)] as number)) ^ (S[0x200 | ((r >>> 8) & 0xff)] as number)) + (S[0x300 | (r & 0xff)] as number)) ^ (P[i + 1] as number);
    }
    block[off] = r ^ (P[17] as number);
    block[off + 1] = l;
  };
  // Blowfish_stream2word: the next 4 bytes of `data` as a big-endian word, wrapping around.
  let pos = 0;
  const word = (data: Uint8Array) => {
    let w = 0;
    for (let i = 0; i < 4; i++) {
      if (pos >= data.length) pos = 0;
      w = (w << 8) | (data[pos++] as number);
    }
    return w;
  };
  const expand = (data: Uint8Array | undefined, k: Uint8Array) => {
    pos = 0;
    for (let i = 0; i < 18; i++) P[i] = (P[i] as number) ^ word(k);
    pos = 0;
    lr[0] = 0;
    lr[1] = 0;
    const fill = (arr: Int32Array, n: number) => {
      for (let i = 0; i < n; i += 2) {
        if (data) {
          lr[0] = (lr[0] as number) ^ word(data);
          lr[1] = (lr[1] as number) ^ word(data);
        }
        encipher(lr, 0);
        arr[i] = lr[0] as number;
        arr[i + 1] = lr[1] as number;
      }
    };
    fill(P, 18);
    fill(S, 1024);
  };

  expand(salt, key);
  const rounds = 2 ** cost;
  for (let i = 0; i < rounds; i++) {
    expand(undefined, key);
    expand(undefined, salt);
  }
  const block = Int32Array.from(MAGIC);
  for (let i = 0; i < 64; i++) for (let b = 0; b < 6; b += 2) encipher(block, b);
  const out = new Uint8Array(24);
  const view = new DataView(out.buffer);
  for (let i = 0; i < 6; i++) view.setInt32(4 * i, block[i] as number, false);
  return encode(out.subarray(0, 23));
}

/** A full `$2b$` hash (tests and tools; the gate only verifies). */
export function bcryptHash(password: Uint8Array, salt: Uint8Array, cost: number, minor: "a" | "b" | "y" = "b"): string {
  return `$2${minor}$${String(cost).padStart(2, "0")}$${encode(salt)}${bcryptDigest(password, salt, cost)}`;
}

/** Checks a password against a bcrypt hash in constant time over the digest. Passwords over 72 bytes never match. */
export function bcryptVerify(password: Uint8Array, hash: string): boolean {
  const h = parseBcrypt(hash);
  if (!h) throw new Error("not a bcrypt hash");
  if (h.cost > BCRYPT_MAX_COST) throw new Error(`bcrypt cost ${h.cost} is above ${BCRYPT_MAX_COST}`);
  if (password.length > BCRYPT_MAX_PASSWORD_BYTES) return false;
  const got = Buffer.from(bcryptDigest(password, h.salt, h.cost));
  return timingSafeEqual(got, Buffer.from(h.digest));
}

interface WorkerRequest {
  id: number;
  password: Uint8Array;
  hash: string;
}

interface WorkerReply {
  id: number;
  ok?: boolean;
  error?: string;
}

export class GateBusyError extends Error {}

/**
 * Verifies in a worker thread, one at a time, with a bounded queue: a burst of wrong passwords cannot
 * stall the agent's event loop (usage, /attest, settlement), and cannot queue unbounded work.
 */
export class BcryptWorker {
  private worker?: Worker;
  private nextId = 1;
  private readonly pending = new Map<number, { ok: (v: boolean) => void; fail: (e: Error) => void; timer: NodeJS.Timeout }>();
  private readonly maxPending: number;
  private readonly timeoutMs: number;

  constructor(opts: { maxPending?: number; timeoutMs?: number } = {}) {
    this.maxPending = opts.maxPending ?? 8;
    this.timeoutMs = opts.timeoutMs ?? 60_000;
  }

  private start(): Worker {
    if (this.worker) return this.worker;
    // execArgv: [] so the worker never inherits the agent's own node flags (an inspector, loaders).
    const w = new Worker(new URL(import.meta.url), { workerData: { role: "sealed-bcrypt" }, execArgv: [] });
    w.unref();
    w.on("message", (m: WorkerReply) => {
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      clearTimeout(p.timer);
      if (m.error !== undefined) p.fail(new Error(m.error));
      else p.ok(m.ok === true);
    });
    const lost = (err: Error) => {
      if (this.worker === w) this.worker = undefined;
      for (const p of this.pending.values()) {
        clearTimeout(p.timer);
        p.fail(err);
      }
      this.pending.clear();
    };
    w.on("error", lost);
    w.on("exit", (code) => lost(new Error(`bcrypt worker exited (${code})`)));
    this.worker = w;
    return w;
  }

  verify(password: Uint8Array, hash: string): Promise<boolean> {
    if (this.pending.size >= this.maxPending) return Promise.reject(new GateBusyError("too many password checks in flight"));
    const w = this.start();
    const id = this.nextId++;
    return new Promise((ok, fail) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        fail(new Error("bcrypt check timed out"));
        // A stuck worker is replaced; its queue is failed above.
        void this.worker?.terminate();
      }, this.timeoutMs);
      timer.unref?.();
      this.pending.set(id, { ok, fail, timer });
      w.postMessage({ id, password, hash } satisfies WorkerRequest);
    });
  }

  async close(): Promise<void> {
    const w = this.worker;
    this.worker = undefined;
    await w?.terminate();
  }
}

if (!isMainThread && (workerData as { role?: string } | null)?.role === "sealed-bcrypt") {
  parentPort?.on("message", (m: WorkerRequest) => {
    let reply: WorkerReply;
    try {
      reply = { id: m.id, ok: bcryptVerify(m.password, m.hash) };
    } catch (err) {
      reply = { id: m.id, error: (err as Error).message };
    }
    parentPort?.postMessage(reply);
  });
}
