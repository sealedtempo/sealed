import { load } from 'cheerio';
import { truncate } from './text.js';

// A field selector is a CSS selector, optionally followed by `@attribute`:
//   "h1.title"      -> trimmed text of the first match
//   "a.next@href"   -> the attribute of the first match (href and src resolved to absolute URLs)
// No match gives null.

export interface FieldSelector {
  css: string;
  attr?: string;
}

export type ItemData = Record<string, string | null>;

// The parts of a Cheerio document extraction uses. Structural, so it accepts both the CommonJS
// Cheerio that Crawlee hands to request handlers and the ESM one.
export interface Selection {
  length: number;
  first(): Selection;
  attr(name: string): string | undefined;
  text(): string;
}
export interface ParsedPage {
  root(): { find(selector: string): Selection };
}

export const MAX_VALUE_LENGTH = 10_000;
const ATTR_SUFFIX = /@([A-Za-z_:][-A-Za-z0-9_:.]*)$/;
const URL_ATTRS = new Set(['href', 'src']);
const probe = load('<!doctype html><html><body></body></html>');

export function parseSelector(raw: string): FieldSelector {
  const trimmed = raw.trim();
  const match = ATTR_SUFFIX.exec(trimmed);
  if (match && match.index > 0 && match[1]) {
    return { css: trimmed.slice(0, match.index).trim(), attr: match[1].toLowerCase() };
  }
  return { css: trimmed };
}

// css-select accepts a few strings that are not useful selectors; refuse those explicitly.
const NOT_A_SELECTOR = /^[@<]|[>+~]\s*$/;

export function selectorError(raw: string): string | null {
  const { css } = parseSelector(raw);
  if (!css) return 'is empty';
  if (NOT_A_SELECTOR.test(css)) return 'is not a valid CSS selector';
  try {
    probe.root().find(css);
    return null;
  } catch {
    return 'is not a valid CSS selector';
  }
}

export function normalizeText(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

function resolveUrl(value: string, baseUrl: string): string {
  try {
    return new URL(value, baseUrl).toString();
  } catch {
    return value;
  }
}

export function extractFields($: ParsedPage, fields: Record<string, string>, pageUrl: string): ItemData {
  const out: ItemData = {};
  for (const [name, raw] of Object.entries(fields)) {
    const { css, attr } = parseSelector(raw);
    const el = $.root().find(css).first();
    let value: string | null = null;
    if (el.length > 0) {
      if (attr) {
        const attrValue = el.attr(attr);
        if (attrValue !== undefined) {
          const trimmed = attrValue.trim();
          value = URL_ATTRS.has(attr) ? resolveUrl(trimmed, pageUrl) : trimmed;
        }
      } else {
        value = normalizeText(el.text());
      }
    }
    out[name] = value === null ? null : truncate(value, MAX_VALUE_LENGTH);
  }
  return out;
}
