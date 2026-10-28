import type { IncomingMessage } from 'node:http';
import { PassThrough } from 'node:stream';
import { text } from 'node:stream/consumers';
import { describe, expect, it } from 'vitest';
import { assertDeclaredSize, capResponse, declaredTooLarge, ResponseTooLargeError } from '../src/crawl/size-cap.js';

function fakeResponse(headers: Record<string, string> = {}) {
  const stream = new PassThrough();
  Object.assign(stream, { statusCode: 200, statusMessage: 'OK', headers, url: 'https://shop.example/p' });
  return stream as unknown as IncomingMessage & PassThrough;
}

describe('response size cap', () => {
  it('reads declared sizes', () => {
    expect(declaredTooLarge('101', 100)).toBe(true);
    expect(declaredTooLarge('100', 100)).toBe(false);
    expect(declaredTooLarge(undefined, 100)).toBe(false);
    expect(declaredTooLarge('nope', 100)).toBe(false);
    const request = { noRetry: false };
    expect(() => assertDeclaredSize(request, '5000', 100)).toThrow(ResponseTooLargeError);
    expect(request.noRetry).toBe(true);
  });

  it('refuses a declared size above the cap before reading anything', () => {
    const request = { noRetry: false };
    expect(() => capResponse(request, fakeResponse({ 'content-length': '2000' }), 1000)).toThrow('response larger than 1000 bytes');
    expect(request.noRetry).toBe(true);
  });

  it('passes small bodies through with the response properties Crawlee reads', async () => {
    const source = fakeResponse({ 'content-type': 'text/html' });
    const capped = capResponse({ noRetry: false }, source, 1000);
    expect(capped.statusCode).toBe(200);
    expect(capped.headers).toEqual({ 'content-type': 'text/html' });
    expect((capped as unknown as { url: string }).url).toBe('https://shop.example/p');
    source.end('<p>hello</p>');
    expect(await text(capped)).toBe('<p>hello</p>');
  });

  it('cuts off a body that grows past the cap while streaming', async () => {
    const request = { noRetry: false };
    const source = fakeResponse();
    const capped = capResponse(request, source, 1000);
    source.write(Buffer.alloc(600, 'a'));
    source.write(Buffer.alloc(600, 'a'));
    await expect(text(capped)).rejects.toBeInstanceOf(ResponseTooLargeError);
    expect(request.noRetry).toBe(true);
    expect(source.destroyed).toBe(true);
  });
});
