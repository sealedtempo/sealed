import { describe, expect, it } from 'vitest';
import { csvCell, csvRow } from '../src/csv.js';

describe('csv', () => {
  it('leaves plain values unquoted', () => {
    expect(csvCell('FX-1001')).toBe('FX-1001');
    expect(csvCell('$4.50')).toBe('$4.50');
    expect(csvCell('Café table')).toBe('Café table');
  });

  it('quotes commas, quotes, CR and LF and doubles quotes', () => {
    expect(csvCell('Brass hinge, 3 inch')).toBe('"Brass hinge, 3 inch"');
    expect(csvCell('Wood screw "No. 8"')).toBe('"Wood screw ""No. 8"""');
    expect(csvCell('line one\nline two')).toBe('"line one\nline two"');
    expect(csvCell('a\r\nb')).toBe('"a\r\nb"');
    expect(csvCell('"')).toBe('""""');
  });

  it('writes null and undefined as empty cells', () => {
    expect(csvRow(['a', null, undefined, ''])).toBe('a,,,\r\n');
  });

  it('ends rows with CRLF', () => {
    expect(csvRow(['url', 'name'])).toBe('url,name\r\n');
  });

  it('neutralizes spreadsheet formulas by default', () => {
    expect(csvCell('=HYPERLINK("http://evil","x")')).toBe(`"'=HYPERLINK(""http://evil"",""x"")"`);
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('-20 C')).toBe("'-20 C");
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell('\tcmd')).toBe("'\tcmd");
    expect(csvCell('a=b')).toBe('a=b');
  });

  it('keeps raw values when formula escaping is off', () => {
    expect(csvCell('-20 C', { escapeFormulas: false })).toBe('-20 C');
    expect(csvCell('=1+1, ok', { escapeFormulas: false })).toBe('"=1+1, ok"');
  });
});
