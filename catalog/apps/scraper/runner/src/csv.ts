// RFC 4180 CSV: CRLF row endings, fields quoted when they contain a comma, quote, CR or LF,
// quotes doubled. Scraped text is untrusted, so by default a cell that a spreadsheet would read
// as a formula (leading = + - @ tab or CR) is prefixed with a single quote (OWASP CSV injection).

export interface CsvOptions {
  escapeFormulas: boolean;
}

const NEEDS_QUOTES = /[",\r\n]/;
const FORMULA_START = /^[=+\-@\t\r]/;

export function csvCell(value: string | null | undefined, options: CsvOptions = { escapeFormulas: true }): string {
  if (value === null || value === undefined) return '';
  let text = value;
  if (options.escapeFormulas && FORMULA_START.test(text)) text = `'${text}`;
  return NEEDS_QUOTES.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function csvRow(values: ReadonlyArray<string | null | undefined>, options?: CsvOptions): string {
  return values.map((v) => csvCell(v, options)).join(',') + '\r\n';
}
