import { z } from "zod";

export const hexBytes = (n: number) =>
  z.string().regex(new RegExp(`^0x[0-9a-fA-F]{${n * 2}}$`), `expected 0x-prefixed ${n}-byte hex`);
export const hexString = z.string().regex(/^0x([0-9a-fA-F]{2})*$/, "expected 0x-prefixed hex");
export const bareHex = z.string().regex(/^(0x)?([0-9a-fA-F]{2})*$/, "expected hex");
export const bytes32 = hexBytes(32);
export const address = hexBytes(20);
export const uint64 = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
/** uint256 money / quantity as a decimal string (INTERFACES conventions). */
export const decimalString = z.string().regex(/^(0|[1-9][0-9]*)$/, "expected a decimal integer string");
export const slug = z.string().regex(/^[a-z][a-z0-9-]{1,30}[a-z0-9]$/, "expected an app id slug");
