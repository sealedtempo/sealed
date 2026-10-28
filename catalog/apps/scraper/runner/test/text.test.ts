import { describe, expect, it } from 'vitest';
import { storableText, truncate } from '../src/text.js';

const EMOJI = '\u{1F600}';

describe('truncate', () => {
  it('leaves short text alone and cuts long text to the limit', () => {
    expect(truncate('abc', 3)).toBe('abc');
    expect(truncate('abcdef', 4)).toBe('abcd');
  });

  it('never splits a surrogate pair', () => {
    const cut = truncate('a'.repeat(9999) + EMOJI, 10_000);
    expect(cut).toBe('a'.repeat(9999));
    expect(cut.isWellFormed()).toBe(true);
    expect(truncate('ab' + EMOJI, 4)).toBe('ab' + EMOJI);
  });
});

describe('storableText', () => {
  it('removes NUL characters and replaces lone surrogates', () => {
    expect(storableText('a\u0000b')).toBe('ab');
    expect(storableText('x\uD83D')).toBe('x�');
    expect(storableText('\uDE00y')).toBe('�y');
    expect(storableText(`ok ${EMOJI}`)).toBe(`ok ${EMOJI}`);
    expect(JSON.stringify(storableText('\uD83D'))).not.toMatch(/\\ud8/i);
  });
});
