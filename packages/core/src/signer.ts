// Enclave signer: a secp256k1 key derived deterministically from the key broker's signerSeed, so
// the same deployment gets the same signer address after every reboot (D-011).
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { canonicalize } from "./cjson.js";
import { type Address, bytesToHex, type Hex, hexToBytes, utf8 } from "./hex.js";

export const ENCLAVE_SIGNER_SALT = "sealed/enclave-signer/v1";
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * privateKey = HKDF-SHA256(ikm = signerSeed, salt = "sealed/enclave-signer/v1", info = [counter], L = 32),
 * taking the first counter (0, 1, ...) whose output is a valid scalar in [1, n-1].
 */
export function deriveEnclavePrivateKey(signerSeed: Hex | Uint8Array): Hex {
  const seed = typeof signerSeed === "string" ? hexToBytes(signerSeed, 32) : signerSeed;
  if (seed.length !== 32) throw new Error("signerSeed must be 32 bytes");
  for (let counter = 0; counter < 256; counter++) {
    const okm = hkdf(sha256, seed, utf8(ENCLAVE_SIGNER_SALT), Uint8Array.of(counter), 32);
    const k = BigInt(bytesToHex(okm));
    if (k > 0n && k < SECP256K1_N) return bytesToHex(okm);
  }
  throw new Error("unreachable: no valid secp256k1 scalar");
}

export function enclaveSignerAddress(signerSeed: Hex | Uint8Array): Address {
  return privateKeyToAccount(deriveEnclavePrivateKey(signerSeed)).address.toLowerCase() as Address;
}

/** EIP-191 personal_sign over the CJSON bytes of a body (health reports, INTERFACES 10). */
export async function signCjsonBody(body: unknown, privateKey: Hex): Promise<Hex> {
  return privateKeyToAccount(privateKey).signMessage({ message: { raw: utf8(canonicalize(body)) } });
}

export async function recoverCjsonBodySigner(body: unknown, signature: Hex): Promise<Address> {
  const addr = await recoverMessageAddress({ message: { raw: utf8(canonicalize(body)) }, signature });
  return addr.toLowerCase() as Address;
}
