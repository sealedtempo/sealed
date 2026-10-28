// D-065: counts sent to the platform are rounded down to two significant figures. Egress counts, payer
// counters and the like are content-free, but an app can still modulate them to pass a few bits per
// report to the platform (review ws-int-agent 3); rounding narrows that channel. Usage quantities in
// signed usage reports stay exact, because billing needs them.

/** Significant figures the platform sees of a count (D-065). */
export const COUNT_SIGNIFICANT_FIGURES = 2;

function roundDigits(digits: string, figures: number): string {
  if (digits.length <= figures) return digits;
  return digits.slice(0, figures) + "0".repeat(digits.length - figures);
}

/** `n` rounded down to `figures` significant figures: 0..99 stay, 123 -> 120, 98765 -> 98000. Non-negative safe integers only. */
export function roundDownSignificant(n: number, figures: number = COUNT_SIGNIFICANT_FIGURES): number {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`not a count: ${n}`);
  if (!Number.isInteger(figures) || figures < 1) throw new RangeError(`invalid significant figures: ${figures}`);
  return Number(roundDigits(String(n), figures));
}

/** The same for a decimal string of any size (amounts in base units): "1234567" -> "1200000". */
export function roundDownSignificantDecimal(s: string, figures: number = COUNT_SIGNIFICANT_FIGURES): string {
  if (!/^[0-9]+$/.test(s)) throw new RangeError(`not a decimal string: ${JSON.stringify(s)}`);
  if (!Number.isInteger(figures) || figures < 1) throw new RangeError(`invalid significant figures: ${figures}`);
  return roundDigits(s.replace(/^0+(?=.)/, ""), figures);
}
