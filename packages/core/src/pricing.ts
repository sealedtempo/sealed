// Usage pricing (INTERFACES 4.2): fee = floor((quantity * price + carry) / per) in FEE_TOKEN base
// units; the remainder carries into the next period of the same app and unit.
import { type Defaults, usdToUnits } from "./defaults.js";
import { UsageUnit, type UsageUnitId, type UsageUnitName } from "./eip712.js";

export interface PriceRule {
  unit: UsageUnitId;
  /** Base units charged per `per` quantity units. */
  price: bigint;
  per: bigint;
}

export interface FeeSchedule {
  tokens: PriceRule;
  pages: PriceRule;
  /** app slug -> rule; quantity is seconds, priced per hour. */
  appHour: Record<string, PriceRule>;
}

export function feeScheduleFromDefaults(d: Defaults): FeeSchedule {
  const dec = d.chain.fee_token_decimals;
  const appHour: Record<string, PriceRule> = {};
  for (const [slug, usd] of Object.entries(d.fees_usd.app_hour)) {
    appHour[slug] = { unit: UsageUnit.app_hour, price: usdToUnits(usd, dec), per: 3600n };
  }
  return {
    tokens: { unit: UsageUnit.tokens, price: usdToUnits(d.fees_usd.gateway_per_1m_tokens, dec), per: 1_000_000n },
    pages: { unit: UsageUnit.pages, price: usdToUnits(d.fees_usd.scraper_per_1k_pages, dec), per: 1000n },
    appHour,
  };
}

/** The rule for an app and unit. Apps without an app_hour price are not charged for time. */
export function priceRuleFor(schedule: FeeSchedule, appSlug: string, unit: UsageUnitName | UsageUnitId): PriceRule {
  const id = typeof unit === "number" ? unit : UsageUnit[unit];
  if (id === UsageUnit.tokens) return schedule.tokens;
  if (id === UsageUnit.pages) return schedule.pages;
  if (id === UsageUnit.app_hour) return schedule.appHour[appSlug] ?? { unit: UsageUnit.app_hour, price: 0n, per: 3600n };
  throw new Error(`unknown usage unit ${String(unit)}`);
}

export interface PricedQuantity {
  fee: bigint;
  /** Remainder numerator (0 <= carry < per) to pass into the next period. */
  carry: bigint;
}

export function priceQuantity(quantity: bigint, rule: PriceRule, carryIn = 0n): PricedQuantity {
  if (quantity < 0n || carryIn < 0n || carryIn >= rule.per) throw new Error("priceQuantity: bad input");
  const raw = quantity * rule.price + carryIn;
  return { fee: raw / rule.per, carry: raw % rule.per };
}

/**
 * Largest quantity whose fee, starting from `carryIn`, does not exceed `maxFee`. Used to split
 * usage so no single report item exceeds the FeeSplitter per-payment cap. Returns null when the
 * rule is free (any quantity fits).
 */
export function maxQuantityWithinFee(rule: PriceRule, carryIn: bigint, maxFee: bigint): bigint | null {
  if (rule.price === 0n) return null;
  // floor((q*price + carry)/per) <= maxFee  <=>  q*price + carry < (maxFee+1)*per
  const limit = (maxFee + 1n) * rule.per - 1n - carryIn;
  return limit < 0n ? 0n : limit / rule.price;
}
