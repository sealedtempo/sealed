// A throwaway self-signed P-256 certificate built in memory (minimal DER encoder), so TLS tests need
// neither openssl nor a private key file in the repository.
import { createHash, generateKeyPairSync, sign } from "node:crypto";

const len = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
const tlv = (tag: number, ...parts: Buffer[]) => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag, ...len(body.length)]), body]);
};
const seq = (...p: Buffer[]) => tlv(0x30, ...p);
const oid = (dotted: string) => {
  const [a, b, ...rest] = dotted.split(".").map(Number) as number[];
  const out = [40 * (a as number) + (b as number)];
  for (const v of rest) {
    const chunk = [v & 0x7f];
    for (let x = v >> 7; x > 0; x >>= 7) chunk.unshift((x & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
};
const name = (cn: string) => seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0c, Buffer.from(cn)))));
const utc = (s: string) => tlv(0x17, Buffer.from(s));
const pem = (label: string, der: Buffer) => `-----BEGIN ${label}-----\n${der.toString("base64").match(/.{1,64}/g)?.join("\n")}\n-----END ${label}-----\n`;

export interface SelfSigned {
  key: string;
  cert: string;
  /** sha256 of the DER SubjectPublicKeyInfo, 0x-prefixed: the expected tlsPubKeyHash. */
  spkiSha256: `0x${string}`;
}

export function selfSignedCert(cn: string): SelfSigned {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  const ecdsaSha256 = seq(oid("1.2.840.10045.4.3.2"));
  const tbs = seq(
    tlv(0xa0, tlv(0x02, Buffer.from([2]))),
    tlv(0x02, Buffer.from([0x01, 0x23, 0x45])),
    ecdsaSha256,
    name(cn),
    seq(utc("200101000000Z"), utc("491231000000Z")),
    name(cn),
    spki,
  );
  const signature = sign("sha256", tbs, privateKey);
  const der = seq(tbs, ecdsaSha256, tlv(0x03, Buffer.from([0]), signature));
  return {
    key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    cert: pem("CERTIFICATE", der),
    spkiSha256: `0x${createHash("sha256").update(spki).digest("hex")}`,
  };
}
