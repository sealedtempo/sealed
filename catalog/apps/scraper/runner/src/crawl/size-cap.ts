import type { IncomingMessage } from 'node:http';
import { Transform } from 'node:stream';
import { DEFAULT_MAX_PAGE_BYTES } from '../limits.js';
import { HttpStatusError } from './common.js';

// Crawlee buffers whole response bodies. One huge page from an allowed host could push the
// container past its memory limit and take every active run with it, so bodies are capped:
// a larger declared Content-Length fails at once, and a body that grows past the cap while it
// streams (chunked, or decompressed beyond its compressed length) is cut off. Neither is retried.

export { DEFAULT_MAX_PAGE_BYTES };

export class ResponseTooLargeError extends HttpStatusError {}

const tooLarge = (maxBytes: number) => new ResponseTooLargeError(`response larger than ${maxBytes} bytes`);

export function declaredTooLarge(contentLength: string | string[] | undefined, maxBytes: number): boolean {
  const n = Number(Array.isArray(contentLength) ? contentLength[0] : contentLength);
  return Number.isFinite(n) && n > maxBytes;
}

export function assertDeclaredSize(request: { noRetry: boolean }, contentLength: string | string[] | undefined, maxBytes: number): void {
  if (!declaredTooLarge(contentLength, maxBytes)) return;
  request.noRetry = true;
  throw tooLarge(maxBytes);
}

// The properties Crawlee reads from the response stream it parses.
const RESPONSE_PROPS = ['statusCode', 'statusMessage', 'headers', 'rawHeaders', 'httpVersion', 'url', 'redirectUrls', 'ip', 'request'] as const;

export function capResponse(request: { noRetry: boolean }, response: IncomingMessage, maxBytes: number): IncomingMessage {
  if (declaredTooLarge(response.headers['content-length'], maxBytes)) {
    request.noRetry = true;
    response.destroy();
    throw tooLarge(maxBytes);
  }
  let seen = 0;
  const capped = new Transform({
    transform(chunk: Buffer, _encoding, done) {
      seen += chunk.length;
      if (seen > maxBytes) {
        request.noRetry = true;
        response.unpipe(capped);
        response.destroy();
        done(tooLarge(maxBytes));
        return;
      }
      done(null, chunk);
    },
  });
  response.on('error', (err) => capped.destroy(err));
  response.pipe(capped);
  const source = response as unknown as Record<string, unknown>;
  const target = capped as unknown as Record<string, unknown>;
  for (const prop of RESPONSE_PROPS) if (prop in source) target[prop] = source[prop];
  return capped as unknown as IncomingMessage;
}
