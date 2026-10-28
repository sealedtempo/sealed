import { load } from 'cheerio';
import { describe, expect, it } from 'vitest';
import { extractFields, MAX_VALUE_LENGTH, parseSelector, selectorError } from '../src/extract.js';

const page = load(`<!doctype html><html><body>
  <h1 class="title">  Brass
     hinge  </h1>
  <span class="price">$4.50</span><span class="price">$9.00</span>
  <a class="next" href="p02.html">Next</a>
  <img class="photo" src="/img/a.png" alt=" A photo ">
  <p class="long">${'x'.repeat(MAX_VALUE_LENGTH + 50)}</p>
</body></html>`);

describe('parseSelector', () => {
  it('splits a trailing @attribute', () => {
    expect(parseSelector('a.next@href')).toEqual({ css: 'a.next', attr: 'href' });
    expect(parseSelector(' img @ALT ')).toEqual({ css: 'img', attr: 'alt' });
  });

  it('leaves selectors without a suffix alone, including @ inside attribute values', () => {
    expect(parseSelector('h1.title')).toEqual({ css: 'h1.title' });
    expect(parseSelector('a[href$="@example.com"]')).toEqual({ css: 'a[href$="@example.com"]' });
  });
});

describe('selectorError', () => {
  it('accepts valid selectors', () => {
    expect(selectorError('div > p.description:first-child')).toBeNull();
    expect(selectorError('a.next@href')).toBeNull();
  });

  it('rejects invalid or empty selectors', () => {
    expect(selectorError('a[')).toBe('is not a valid CSS selector');
    expect(selectorError('##')).toBe('is not a valid CSS selector');
    expect(selectorError('@href')).toBe('is not a valid CSS selector');
    expect(selectorError('<p>')).toBe('is not a valid CSS selector');
    expect(selectorError('div >')).toBe('is not a valid CSS selector');
    expect(selectorError('p:nope')).toBe('is not a valid CSS selector');
    expect(selectorError('p,,')).toBe('is not a valid CSS selector');
    expect(selectorError('   ')).toBe('is empty');
  });
});

describe('extractFields', () => {
  it('takes normalized text of the first match, attributes, and null for no match', () => {
    const data = extractFields(
      page,
      { title: 'h1.title', price: '.price', next: 'a.next@href', photo: 'img.photo@src', alt: 'img@alt', missing: '.nope', noattr: 'h1@data-x' },
      'https://shop.test/products/p01.html',
    );
    expect(data).toEqual({
      title: 'Brass hinge',
      price: '$4.50',
      next: 'https://shop.test/products/p02.html',
      photo: 'https://shop.test/img/a.png',
      alt: 'A photo',
      missing: null,
      noattr: null,
    });
  });

  it('caps values', () => {
    expect(extractFields(page, { long: '.long' }, 'https://shop.test/').long).toHaveLength(MAX_VALUE_LENGTH);
  });

  it('never treats a selector as markup to create', () => {
    expect(extractFields(page, { x: '<p>hello</p>' }, 'https://shop.test/')).toEqual({ x: null });
  });
});
