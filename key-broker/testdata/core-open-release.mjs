// Opens a key broker release vector with @sealed/core's TypeScript HPKE (the code sealed-agent runs).
// Usage: node core-open-release.mjs <path to packages/core/dist/hpke.js> <vector.json>
// Prints the plaintext. Run by TestHPKEInteropWithCore.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [hpkePath, vectorPath] = process.argv.slice(2);
const { deriveKeyPair, openKbRelease } = await import(pathToFileURL(hpkePath).href);
const v = JSON.parse(readFileSync(vectorPath, "utf8"));
const hex = (s) => Uint8Array.from(Buffer.from(s.replace(/^0x/, ""), "hex"));
const kp = await deriveKeyPair(hex(v.recipientIkm));
if (Buffer.from(kp.publicKey).toString("hex") !== v.ephemeralPub.replace(/^0x/, "")) {
  throw new Error("public key derived by @sealed/core differs from the vector");
}
const pt = await openKbRelease(kp.privateKey, hex(v.nonce), hex(v.enc), hex(v.ciphertext));
process.stdout.write(new TextDecoder().decode(pt));
