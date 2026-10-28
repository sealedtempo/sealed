// EIP-712 structures of INTERFACES section 4, encoded by hand (typeHash / encodeData / domain
// separator) so tests can cross-check them against viem's hashTypedData and the contracts' views.
import { encodeAbiParameters, keccak256, recoverTypedDataAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { type Address, concatBytes, type Hex, hexToBytes, utf8 } from "./hex.js";

export const TEMPO_CHAIN_ID = 4217;

export interface Eip712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}

export const REGISTRY_DOMAIN_NAME = "Sealed DeploymentRegistry";
export const USAGE_DOMAIN_NAME = "Sealed Usage";

export function registryDomain(verifyingContract: Address, chainId: number = TEMPO_CHAIN_ID): Eip712Domain {
  return { name: REGISTRY_DOMAIN_NAME, version: "1", chainId, verifyingContract };
}

export function usageDomain(feeSplitter: Address, chainId: number = TEMPO_CHAIN_ID): Eip712Domain {
  return { name: USAGE_DOMAIN_NAME, version: "1", chainId, verifyingContract: feeSplitter };
}

// Type definitions in viem's typed-data shape (also usable with signTypedData / hashTypedData).
export const recordTypes = {
  Record: [
    { name: "deploymentId", type: "bytes32" },
    { name: "customer", type: "address" },
    { name: "stackHash", type: "bytes32" },
    { name: "imageId", type: "bytes32" },
    { name: "quoteHash", type: "bytes32" },
    { name: "eventLogHash", type: "bytes32" },
    { name: "configHash", type: "bytes32" },
    { name: "enclaveSigner", type: "address" },
    { name: "attestedAt", type: "uint64" },
  ],
} as const;

export const heartbeatTypes = {
  Heartbeat: [
    { name: "deploymentId", type: "bytes32" },
    { name: "quoteHash", type: "bytes32" },
    { name: "attestedAt", type: "uint64" },
  ],
} as const;

export const usageReportTypes = {
  UsageReport: [
    { name: "deploymentId", type: "bytes32" },
    { name: "periodStart", type: "uint64" },
    { name: "periodEnd", type: "uint64" },
    { name: "items", type: "UsageItem[]" },
  ],
  UsageItem: [
    { name: "appId", type: "bytes32" },
    { name: "unit", type: "uint8" },
    { name: "quantity", type: "uint256" },
    { name: "fee", type: "uint256" },
  ],
} as const;

export const RECORD_TYPE =
  "Record(bytes32 deploymentId,address customer,bytes32 stackHash,bytes32 imageId,bytes32 quoteHash,bytes32 eventLogHash,bytes32 configHash,address enclaveSigner,uint64 attestedAt)";
export const HEARTBEAT_TYPE = "Heartbeat(bytes32 deploymentId,bytes32 quoteHash,uint64 attestedAt)";
export const USAGE_ITEM_TYPE = "UsageItem(bytes32 appId,uint8 unit,uint256 quantity,uint256 fee)";
// EIP-712: referenced struct types are appended in alphabetical order after the primary type.
export const USAGE_REPORT_TYPE = `UsageReport(bytes32 deploymentId,uint64 periodStart,uint64 periodEnd,UsageItem[] items)${USAGE_ITEM_TYPE}`;
const DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

export const RECORD_TYPEHASH = keccak256(utf8(RECORD_TYPE));
export const HEARTBEAT_TYPEHASH = keccak256(utf8(HEARTBEAT_TYPE));
export const USAGE_ITEM_TYPEHASH = keccak256(utf8(USAGE_ITEM_TYPE));
export const USAGE_REPORT_TYPEHASH = keccak256(utf8(USAGE_REPORT_TYPE));
const DOMAIN_TYPEHASH = keccak256(utf8(DOMAIN_TYPE));

export interface DeploymentRecord {
  deploymentId: Hex;
  customer: Address;
  stackHash: Hex;
  imageId: Hex;
  quoteHash: Hex;
  eventLogHash: Hex;
  configHash: Hex;
  enclaveSigner: Address;
  attestedAt: bigint;
}

export interface Heartbeat {
  deploymentId: Hex;
  quoteHash: Hex;
  attestedAt: bigint;
}

/** Usage units (INTERFACES 4.2). */
export const UsageUnit = { tokens: 1, pages: 2, app_hour: 3 } as const;
export type UsageUnitName = keyof typeof UsageUnit;
export type UsageUnitId = (typeof UsageUnit)[UsageUnitName];

export interface UsageItem {
  appId: Hex;
  unit: UsageUnitId;
  quantity: bigint;
  fee: bigint;
}

export interface UsageReport {
  deploymentId: Hex;
  periodStart: bigint;
  periodEnd: bigint;
  items: UsageItem[];
}

export function domainSeparator(domain: Eip712Domain): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
      [DOMAIN_TYPEHASH, keccak256(utf8(domain.name)), keccak256(utf8(domain.version)), BigInt(domain.chainId), domain.verifyingContract],
    ),
  );
}

function typedDigest(domain: Eip712Domain, structHash: Hex): Hex {
  return keccak256(concatBytes(Uint8Array.of(0x19, 0x01), hexToBytes(domainSeparator(domain)), hexToBytes(structHash)));
}

export function recordStructHash(r: DeploymentRecord): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" }, { type: "bytes32" }, { type: "address" }, { type: "bytes32" }, { type: "bytes32" },
        { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "address" }, { type: "uint64" },
      ],
      [
        RECORD_TYPEHASH, r.deploymentId, r.customer, r.stackHash, r.imageId, r.quoteHash, r.eventLogHash,
        r.configHash, r.enclaveSigner, r.attestedAt,
      ],
    ),
  );
}

export function heartbeatStructHash(h: Heartbeat): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint64" }],
      [HEARTBEAT_TYPEHASH, h.deploymentId, h.quoteHash, h.attestedAt],
    ),
  );
}

export function usageItemStructHash(item: UsageItem): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint8" }, { type: "uint256" }, { type: "uint256" }],
      [USAGE_ITEM_TYPEHASH, item.appId, item.unit, item.quantity, item.fee],
    ),
  );
}

export function usageReportStructHash(report: UsageReport): Hex {
  const itemsHash = keccak256(concatBytes(...report.items.map((i) => hexToBytes(usageItemStructHash(i)))));
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint64" }, { type: "uint64" }, { type: "bytes32" }],
      [USAGE_REPORT_TYPEHASH, report.deploymentId, report.periodStart, report.periodEnd, itemsHash],
    ),
  );
}

/** DeploymentRegistry.recordDigest(r) */
export function recordDigest(r: DeploymentRecord, domain: Eip712Domain): Hex {
  return typedDigest(domain, recordStructHash(r));
}

/** DeploymentRegistry.heartbeatDigest(deploymentId, quoteHash, attestedAt) */
export function heartbeatDigest(h: Heartbeat, domain: Eip712Domain): Hex {
  return typedDigest(domain, heartbeatStructHash(h));
}

/** usageHash: the digest passed to FeeSplitter.payFees for every app of the report. */
export function usageReportDigest(report: UsageReport, domain: Eip712Domain): Hex {
  return typedDigest(domain, usageReportStructHash(report));
}

export function usageReportTypedData(report: UsageReport, domain: Eip712Domain) {
  return {
    domain,
    types: usageReportTypes,
    primaryType: "UsageReport" as const,
    message: report,
  };
}

/** Signs a usage report with a secp256k1 key (the enclave signer). Returns a 65-byte signature. */
export async function signUsageReport(report: UsageReport, domain: Eip712Domain, privateKey: Hex): Promise<Hex> {
  return privateKeyToAccount(privateKey).signTypedData(usageReportTypedData(report, domain));
}

export async function recoverUsageReportSigner(report: UsageReport, domain: Eip712Domain, signature: Hex): Promise<Address> {
  return recoverTypedDataAddress({ ...usageReportTypedData(report, domain), signature });
}

// --- JSON form of a usage report (uint256 as decimal strings, INTERFACES conventions) ---------

export interface UsageItemJson {
  appId: Hex;
  unit: UsageUnitId;
  quantity: string;
  fee: string;
}

export interface UsageReportJson {
  deploymentId: Hex;
  periodStart: number;
  periodEnd: number;
  items: UsageItemJson[];
}

export function usageReportToJson(r: UsageReport): UsageReportJson {
  return {
    deploymentId: r.deploymentId,
    periodStart: Number(r.periodStart),
    periodEnd: Number(r.periodEnd),
    items: r.items.map((i) => ({ appId: i.appId, unit: i.unit, quantity: i.quantity.toString(), fee: i.fee.toString() })),
  };
}

export function usageReportFromJson(j: UsageReportJson): UsageReport {
  return {
    deploymentId: j.deploymentId,
    periodStart: BigInt(j.periodStart),
    periodEnd: BigInt(j.periodEnd),
    items: j.items.map((i) => ({ appId: i.appId, unit: i.unit, quantity: BigInt(i.quantity), fee: BigInt(i.fee) })),
  };
}
