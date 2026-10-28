// A minimal POSIX ustar writer for tests (the composer's bundle layout: sorted entries, mode 0644, mtime 0).
export function ustar(files: Record<string, string | Uint8Array>): Uint8Array {
  const enc = new TextEncoder();
  const blocks: Uint8Array[] = [];
  for (const name of Object.keys(files).sort()) {
    const raw = files[name] as string | Uint8Array;
    const body = typeof raw === "string" ? enc.encode(raw) : raw;
    const h = new Uint8Array(512);
    const put = (off: number, len: number, v: string) => h.set(enc.encode(v).subarray(0, len), off);
    put(0, 100, name);
    put(100, 8, "0000644\0");
    put(108, 8, "0000000\0");
    put(116, 8, "0000000\0");
    put(124, 12, `${body.length.toString(8).padStart(11, "0")}\0`);
    put(136, 12, "00000000000\0");
    h.fill(0x20, 148, 156);
    h[156] = 0x30;
    put(257, 6, "ustar\0");
    put(263, 2, "00");
    let sum = 0;
    for (const b of h) sum += b;
    put(148, 8, `${sum.toString(8).padStart(6, "0")}\0 `);
    blocks.push(h);
    const padded = new Uint8Array(Math.ceil(body.length / 512) * 512);
    padded.set(body);
    blocks.push(padded);
  }
  blocks.push(new Uint8Array(1024));
  const out = new Uint8Array(blocks.reduce((s, b) => s + b.length, 0));
  let off = 0;
  for (const b of blocks) {
    out.set(b, off);
    off += b.length;
  }
  return out;
}
