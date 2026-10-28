// Privileged helper for the payment-needed switch. sealed-agent forks it while still root, before it
// drops privileges, because Caddy's admin socket is root-only. The helper takes one init message
// with the socket path and the two measured Caddyfiles, then accepts only {id, variant} requests and
// answers each with {id, ok, error?}. It exits when the agent goes away. Standalone on purpose (node
// builtins only, erasable TypeScript) so it runs the same from dist/ and from the sources in tests.
import http from "node:http";

interface Init {
  socket: string;
  normal: string;
  paymentNeeded: string;
}

let files: Init | undefined;

function load(caddyfile: string, socket: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(caddyfile, "utf8");
    const req = http.request(
      {
        socketPath: socket,
        path: "/load",
        method: "POST",
        headers: { host: "localhost", "content-type": "text/caddyfile", "content-length": String(body.length) },
        timeout: 30_000,
      },
      (res) => {
        let text = "";
        res.on("data", (c: Buffer) => {
          if (text.length < 1000) text += c.toString("utf8");
        });
        res.on("end", () => {
          const status = res.statusCode ?? 0;
          if (status >= 200 && status < 300) resolve();
          else reject(new Error(`caddy /load returned ${status}: ${text.slice(0, 300)}`));
        });
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error("caddy /load timed out")));
    req.on("error", reject);
    req.end(body);
  });
}

function isInit(v: unknown): v is Init {
  const i = v as Partial<Init> | null;
  return typeof i === "object" && i !== null && typeof i.socket === "string" && typeof i.normal === "string" && typeof i.paymentNeeded === "string";
}

process.on("message", (msg: unknown) => {
  const m = (msg ?? {}) as { init?: unknown; id?: unknown; variant?: unknown };
  if (m.init !== undefined) {
    if (!files && isInit(m.init)) files = { socket: m.init.socket, normal: m.init.normal, paymentNeeded: m.init.paymentNeeded };
    return;
  }
  if (typeof m.id !== "number") return;
  const id = m.id;
  const reply = (ok: boolean, error?: string) => process.send?.({ id, ok, ...(error ? { error } : {}) });
  if (!files) return reply(false, "not initialized");
  if (m.variant !== "normal" && m.variant !== "payment-needed") return reply(false, "unknown variant");
  const text = m.variant === "normal" ? files.normal : files.paymentNeeded;
  load(text, files.socket).then(
    () => reply(true),
    (err: Error) => reply(false, err.message),
  );
});

process.on("disconnect", () => process.exit(0));
