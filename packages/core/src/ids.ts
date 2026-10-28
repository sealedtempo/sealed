// Ids and hashes of INTERFACES section 2.
import { sha256 } from "@noble/hashes/sha2";
import { encodeAbiParameters, keccak256 } from "viem";
import { cjsonSha256 } from "./cjson.js";
import { type Address, bytesToHex, concatBytes, type Hex, hexToBytes, utf8 } from "./hex.js";

export function sha256Hex(data: Uint8Array | string): Hex {
  return bytesToHex(sha256(typeof data === "string" ? utf8(data) : data));
}

/** appId = keccak256(bytes(slug)) */
export function appId(slug: string): Hex {
  return keccak256(utf8(slug));
}

/** releaseId = keccak256(abi.encode(appId, version, bundleHash)) */
export function releaseId(app: Hex, version: string, bundleHash: Hex): Hex {
  return keccak256(
    encodeAbiParameters([{ type: "bytes32" }, { type: "string" }, { type: "bytes32" }], [app, version, bundleHash]),
  );
}

/** deploymentId = keccak256(abi.encode(customer, stackHash, salt)) */
export function deploymentId(customer: Address, stackHash: Hex, salt: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "bytes32" }, { type: "bytes32" }],
      [customer.toLowerCase() as Address, stackHash, salt],
    ),
  );
}

/** measurementsHash = keccak256(mrtd || rtmr0 || rtmr1 || rtmr2), each exactly 48 bytes. */
export function measurementsHash(mrtd: Hex, rtmr0: Hex, rtmr1: Hex, rtmr2: Hex): Hex {
  return keccak256(
    concatBytes(hexToBytes(mrtd, 48), hexToBytes(rtmr0, 48), hexToBytes(rtmr1, 48), hexToBytes(rtmr2, 48)),
  );
}

/** imageId = keccak256(abi.encode(name, version, measurementsHash)) */
export function imageId(name: string, version: string, measurements: Hex): Hex {
  return keccak256(
    encodeAbiParameters([{ type: "string" }, { type: "string" }, { type: "bytes32" }], [name, version, measurements]),
  );
}

/** configHash = sha256(CJSON(public config)) */
export function configHash(config: unknown): Hex {
  return cjsonSha256(config);
}

/** stackHash = sha256(app-compose.json bytes), the dstack compose hash. */
export function stackHash(appCompose: string): Hex {
  return sha256Hex(appCompose);
}

/** quoteHash = sha256(raw quote bytes) */
export function quoteHash(quote: Hex | Uint8Array): Hex {
  return sha256Hex(typeof quote === "string" ? hexToBytes(quote) : quote);
}

/** eventLogHash = sha256(CJSON(event log array)) */
export function eventLogHash(eventLog: readonly unknown[]): Hex {
  return cjsonSha256(eventLog);
}

/** egressPolicyHash = sha256(CJSON(egress.yaml parsed)) */
export function egressPolicyHash(policy: unknown): Hex {
  return cjsonSha256(policy);
}

/** sbomHash = sha256(CJSON({"<image name>": "<sha256 hex of sbom file>", ...})) */
export function sbomHash(sbomFileHashes: Record<string, string>): Hex {
  return cjsonSha256(sbomFileHashes);
}
