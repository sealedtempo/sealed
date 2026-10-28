// HPKE (RFC 9180) base mode, suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM.
// Wire format: enc (32 bytes) || ciphertext. For the key broker release (INTERFACES section 9)
// info = "sealed/kb-release/v1" and aad = nonce.
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { concatBytes, utf8 } from "./hex.js";

export const KB_RELEASE_INFO = "sealed/kb-release/v1";
export const ENC_LENGTH = 32;
export const TAG_LENGTH = 16;

let suiteInstance: CipherSuite | undefined;
function suite(): CipherSuite {
  suiteInstance ??= new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
  return suiteInstance;
}

export interface HpkeKeyPair {
  privateKey: CryptoKey;
  /** Raw 32-byte X25519 public key. */
  publicKey: Uint8Array;
}

export interface HpkeParams {
  info: Uint8Array | string;
  aad?: Uint8Array;
}

const toBytes = (v: Uint8Array | string) => (typeof v === "string" ? utf8(v) : v);
const ab = (u: Uint8Array): ArrayBuffer => u.slice().buffer as ArrayBuffer;

/** Fresh X25519 key pair. The private key stays a non-extractable-by-default CryptoKey. */
export async function generateKeyPair(): Promise<HpkeKeyPair> {
  const kp = await suite().kem.generateKeyPair();
  return { privateKey: kp.privateKey, publicKey: new Uint8Array(await suite().kem.serializePublicKey(kp.publicKey)) };
}

/** Deterministic key pair (RFC 9180 DeriveKeyPair), for test vectors and cross-language checks. */
export async function deriveKeyPair(ikm: Uint8Array): Promise<HpkeKeyPair> {
  const kp = await suite().kem.deriveKeyPair(ab(ikm));
  return { privateKey: kp.privateKey, publicKey: new Uint8Array(await suite().kem.serializePublicKey(kp.publicKey)) };
}

/**
 * Seals plaintext to a raw X25519 public key. Returns enc || ciphertext.
 * `ephemeralIkm` makes the ephemeral key deterministic; only test vectors pass it.
 */
export async function seal(
  recipientPublicKey: Uint8Array,
  plaintext: Uint8Array,
  params: HpkeParams,
  ephemeralIkm?: Uint8Array,
): Promise<Uint8Array> {
  if (recipientPublicKey.length !== 32) throw new Error("hpke: recipient public key must be 32 bytes");
  const s = suite();
  const pk = await s.kem.deserializePublicKey(ab(recipientPublicKey));
  const sender = await s.createSenderContext({
    recipientPublicKey: pk,
    info: ab(toBytes(params.info)),
    ...(ephemeralIkm ? { ekm: ab(ephemeralIkm) } : {}),
  });
  const ct = await sender.seal(ab(plaintext), params.aad ? ab(params.aad) : undefined);
  return concatBytes(new Uint8Array(sender.enc), new Uint8Array(ct));
}

/** Opens enc || ciphertext with the recipient's private key. Throws on any authentication failure. */
export async function open(recipientPrivateKey: CryptoKey, wire: Uint8Array, params: HpkeParams): Promise<Uint8Array> {
  if (wire.length < ENC_LENGTH + TAG_LENGTH) throw new Error("hpke: ciphertext too short");
  const { enc, ciphertext } = splitWire(wire);
  return openParts(recipientPrivateKey, enc, ciphertext, params);
}

/** Opens a separately transported enc and ciphertext (the key broker response shape). */
export async function openParts(
  recipientPrivateKey: CryptoKey,
  enc: Uint8Array,
  ciphertext: Uint8Array,
  params: HpkeParams,
): Promise<Uint8Array> {
  if (enc.length !== ENC_LENGTH) throw new Error("hpke: enc must be 32 bytes");
  const recipient = await suite().createRecipientContext({
    recipientKey: recipientPrivateKey,
    enc: ab(enc),
    info: ab(toBytes(params.info)),
  });
  return new Uint8Array(await recipient.open(ab(ciphertext), params.aad ? ab(params.aad) : undefined));
}

export function splitWire(wire: Uint8Array): { enc: Uint8Array; ciphertext: Uint8Array } {
  return { enc: wire.slice(0, ENC_LENGTH), ciphertext: wire.slice(ENC_LENGTH) };
}

/** Seals the key-broker release plaintext: info "sealed/kb-release/v1", aad = nonce. */
export async function sealKbRelease(
  ephemeralPub: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ephemeralIkm?: Uint8Array,
): Promise<{ enc: Uint8Array; ciphertext: Uint8Array }> {
  return splitWire(await seal(ephemeralPub, plaintext, { info: KB_RELEASE_INFO, aad: nonce }, ephemeralIkm));
}

/**
 * Opens a key-broker release. Accepts `ciphertext` either as the bare AEAD output (INTERFACES 9)
 * or as enc || ct (the Go one-shot wire form), whichever authenticates.
 */
export async function openKbRelease(
  ephemeralPrivateKey: CryptoKey,
  nonce: Uint8Array,
  enc: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const params = { info: KB_RELEASE_INFO, aad: nonce };
  try {
    return await openParts(ephemeralPrivateKey, enc, ciphertext, params);
  } catch (err) {
    const prefixed = ciphertext.length > ENC_LENGTH && enc.every((byte, i) => ciphertext[i] === byte);
    if (!prefixed) throw err;
    return openParts(ephemeralPrivateKey, enc, ciphertext.slice(ENC_LENGTH), params);
  }
}
