// A fake platform API recording what the agent sends (INTERFACES 10).
import type { EvidenceBundle } from "@sealed/core";
import { serve, type TestServer } from "./http.js";

export interface FakePlatform extends TestServer {
  evidence: EvidenceBundle[];
  usage: { report: Record<string, unknown>; signature: `0x${string}` }[];
  health: { deploymentId: string; signature: `0x${string}`; body: Record<string, unknown> }[];
  failEvidence: number;
}

export async function startFakePlatform(): Promise<FakePlatform> {
  const rec = {
    evidence: [] as FakePlatform["evidence"],
    usage: [] as FakePlatform["usage"],
    health: [] as FakePlatform["health"],
    failEvidence: 0,
  };
  const server = await serve((req, body) => {
    const json = body ? JSON.parse(body) : undefined;
    if (req.method === "POST" && req.url === "/v1/evidence") {
      if (rec.failEvidence > 0) {
        rec.failEvidence--;
        return { status: 503, body: { error: "oracle busy" } };
      }
      rec.evidence.push(json);
      return { status: 200, body: { deploymentId: json.deploymentId, txHash: `0x${"ab".repeat(32)}`, kind: rec.evidence.length === 1 ? "register" : "heartbeat" } };
    }
    if (req.method === "POST" && req.url === "/v1/usage") {
      rec.usage.push(json);
      return { status: 200, body: { ok: true } };
    }
    if (req.method === "POST" && req.url === "/v1/health") {
      rec.health.push(json);
      return { status: 200, body: { ok: true } };
    }
    return { status: 404, body: { error: "not found" } };
  });
  return Object.assign(rec, server);
}
