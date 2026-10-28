// The catalog's release asset host for the devnet. Bundles are served at exactly the URL the release asset rule
// gives (D-046, integration brief item 18):
//   <release_asset_base>/<appId>-v<release_version>/<appId>-<release_version>.bundle.tar
// The key broker, sealed-verifierd and the CLI each compute that URL with runtime/composer's NewReleaseAssets and
// check sha256 against the onchain bundleHash, so a wrong path here fails the run.
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";

/** The URL path of a bundle below the asset base (D-046). */
export function bundleAssetPath(slug: string, version: string): string {
  if (!/^[a-z][a-z0-9-]{1,30}[a-z0-9]$/.test(slug)) throw new Error(`app id ${slug} is not a catalog slug`);
  if (!/^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/.test(version)) throw new Error(`release version ${version} cannot name release assets`);
  return `/${slug}-v${version}/${slug}-${version}.bundle.tar`;
}

export const sha256Hex = (b: Uint8Array) => `0x${createHash("sha256").update(b).digest("hex")}` as const;

export interface AssetServer {
  /** e.g. http://127.0.0.1:41234/sealedtempo/sealed/releases/download */
  base: string;
  /** Request paths served or refused, in order. */
  hits: Array<{ path: string; status: number }>;
  add(slug: string, version: string, bundle: Uint8Array): string;
  /** Serves `bytes` at an absolute URL below the base (for example one `sealed release build` printed). */
  addUrl(url: string, bytes: Uint8Array): void;
  url(slug: string, version: string): string;
  close(): Promise<void>;
}

const PREFIX = "/sealedtempo/sealed/releases/download";

export async function startAssetServer(port = 0, host = "127.0.0.1"): Promise<AssetServer> {
  const files = new Map<string, Uint8Array>();
  const hits: AssetServer["hits"] = [];
  const srv: Server = createServer((req, res) => {
    const path = (req.url ?? "").split("?")[0] ?? "";
    const f = req.method === "GET" || req.method === "HEAD" ? files.get(path) : undefined;
    if (!f) {
      hits.push({ path, status: 404 });
      res.writeHead(404, { "content-type": "text/plain" }).end("not found\n");
      return;
    }
    hits.push({ path, status: 200 });
    res.writeHead(200, { "content-type": "application/x-tar", "content-length": String(f.length) });
    res.end(req.method === "HEAD" ? undefined : Buffer.from(f));
  });
  await new Promise<void>((ok, fail) => {
    srv.once("error", fail);
    srv.listen(port, host, () => ok());
  });
  const addr = srv.address();
  if (!addr || typeof addr !== "object") throw new Error("asset server has no address");
  const base = `http://${host}:${addr.port}${PREFIX}`;
  return {
    base,
    hits,
    add(slug, version, bundle) {
      files.set(PREFIX + bundleAssetPath(slug, version), bundle);
      return base + bundleAssetPath(slug, version);
    },
    addUrl(url, bytes) {
      if (!url.startsWith(`${base}/`)) throw new Error(`${url} is not below ${base}`);
      files.set(new URL(url).pathname, bytes);
    },
    url: (slug, version) => base + bundleAssetPath(slug, version),
    close: () =>
      new Promise<void>((r) => {
        srv.close(() => r());
        srv.closeAllConnections();
      }),
  };
}

/** Reads a POSIX ustar archive (the composer's deterministic bundle format) into path -> bytes. */
export function readTar(tar: Uint8Array): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  const text = (b: Uint8Array) => new TextDecoder().decode(b.subarray(0, b.indexOf(0) < 0 ? b.length : b.indexOf(0)));
  let off = 0;
  while (off + 512 <= tar.length) {
    const h = tar.subarray(off, off + 512);
    if (h.every((x) => x === 0)) break;
    const name = text(h.subarray(0, 100));
    const size = Number.parseInt(text(h.subarray(124, 136)).trim() || "0", 8);
    const type = String.fromCharCode(h[156] ?? 0);
    const prefix = text(h.subarray(345, 500));
    const path = prefix ? `${prefix}/${name}` : name;
    const start = off + 512;
    if (!Number.isFinite(size) || start + size > tar.length) throw new Error(`tar entry ${path} is truncated`);
    if (type === "0" || type === "\0") out.set(path, tar.slice(start, start + size));
    off = start + Math.ceil(size / 512) * 512;
  }
  return out;
}
