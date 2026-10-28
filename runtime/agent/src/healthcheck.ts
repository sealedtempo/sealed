// Container healthcheck: exits 0 when the agent reports ready. No curl in the image.
import http from "node:http";

const port = Number((process.env.SEALED_LISTEN ?? "0.0.0.0:7070").split(":")[1] ?? 7070);
const req = http.get({ host: "127.0.0.1", port, path: "/healthz", timeout: 3000 }, (res) => process.exit(res.statusCode === 200 ? 0 : 1));
req.on("error", () => process.exit(1));
req.on("timeout", () => req.destroy(new Error("timeout")));
