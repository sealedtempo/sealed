import type { FieldError } from '../job.js';

// Turns the UI's HTML form into the same job object the JSON API takes, so both go through
// parseJobSpec. Start URLs are one per line; fields are "name = selector", one per line.

export interface JobForm {
  start_urls: string;
  max_pages: string;
  crawler: string;
  same_domain: boolean;
  respect_robots: boolean;
  extract: string;
  max_concurrency: string;
  max_requests_per_minute: string;
}

export const EMPTY_FORM: JobForm = {
  start_urls: '',
  max_pages: '100',
  crawler: 'cheerio',
  same_domain: true,
  respect_robots: true,
  extract: '',
  max_concurrency: '',
  max_requests_per_minute: '',
};

export function readForm(body: Record<string, string | File | (string | File)[]>): JobForm {
  const text = (name: string): string => {
    const v = body[name];
    const first = Array.isArray(v) ? v[0] : v;
    return typeof first === 'string' ? first : '';
  };
  return {
    start_urls: text('start_urls'),
    max_pages: text('max_pages'),
    crawler: text('crawler') || 'cheerio',
    same_domain: text('same_domain') === 'on',
    respect_robots: text('respect_robots') === 'on',
    extract: text('extract'),
    max_concurrency: text('max_concurrency'),
    max_requests_per_minute: text('max_requests_per_minute'),
  };
}

function numberOrRaw(value: string): number | string | undefined {
  const trimmed = value.trim();
  if (trimmed === '') return undefined;
  const n = Number(trimmed);
  return Number.isFinite(n) ? n : trimmed;
}

const lines = (text: string) =>
  text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'));

export function formToJob(form: JobForm): { job: Record<string, unknown>; errors: FieldError[] } {
  const errors: FieldError[] = [];
  // A Map, so every name (even "__proto__") reaches parseJobSpec as an own key and gets checked.
  const extract = new Map<string, string>();
  lines(form.extract).forEach((line, i) => {
    const eq = line.indexOf('=');
    if (eq <= 0) {
      errors.push({ field: 'extract', message: `line ${i + 1} must look like name = selector` });
      return;
    }
    const name = line.slice(0, eq).trim();
    if (extract.has(name)) {
      errors.push({ field: 'extract', message: `line ${i + 1} repeats the field name ${name}` });
      return;
    }
    extract.set(name, line.slice(eq + 1).trim());
  });
  const job: Record<string, unknown> = {
    start_urls: lines(form.start_urls),
    crawler: form.crawler,
    same_domain: form.same_domain,
    respect_robots: form.respect_robots,
    extract: Object.fromEntries(extract),
  };
  for (const key of ['max_pages', 'max_concurrency', 'max_requests_per_minute'] as const) {
    const value = numberOrRaw(form[key]);
    if (value !== undefined) job[key] = value;
  }
  return { job, errors };
}
