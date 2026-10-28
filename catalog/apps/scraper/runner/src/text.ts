// Scraped text has to survive Postgres: text and jsonb reject NUL characters, and jsonb also
// rejects the "\udXXX" escapes JSON.stringify writes for lone surrogates.

const ENDS_IN_HIGH_SURROGATE = /[\uD800-\uDBFF]$/;

// At most `max` UTF-16 code units, never cutting a surrogate pair (emoji, rare CJK) in half.
export function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  return ENDS_IN_HIGH_SURROGATE.test(cut) ? cut.slice(0, -1) : cut;
}

// NUL characters removed and lone surrogates replaced with U+FFFD.
export function storableText(text: string): string {
  return text.replace(/\u0000/g, '').toWellFormed();
}
