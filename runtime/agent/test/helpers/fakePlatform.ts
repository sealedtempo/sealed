// A fake platform API recording what the agent sends (INTERFACES 10), with the stored usage reports of
// API_CONTRACT 7 and 15 (D-062): POST /v1/usage refuses a report whose period overlaps a stored one with
// 409 conflict, and GET /v1/deployments/:id/usage-reports serves them, page by page, to a signed read by
// the deployment's enclave signer (learned from its first evidence bundle, or set by the test).
import {
  type EvidenceBundle,
  type Hex,
  periodsOverlap,
  recoverCjsonBodySigner,
  usageDomain,
  usageReportDigest,
  usageReportFromJson,
  usageReportsReadMessage,
  type UsageReportJson,
} from "@sealed/core";
import { serve, type TestServer } from "./http.js";

export interface StoredReport {
  usageHash: Hex;
  periodStart: number;
  periodEnd: number;
  report: UsageReportJson;
  signature: Hex;
  receivedAt: number;
}

export interface FakePlatform extends TestServer {
  evidence: EvidenceBundle[];
  usage: { report: Record<string, unknown>; signature: `0x${string}` }[];
  health: { deploymentId: string; signature: `0x${string}`; body: Record<string, unknown> }[];
  failEvidence: number;
  /** The reports the platform stores, in period order (D-062). */
  stored: StoredReport[];
  /** Refused POST /v1/usage bodies (409 overlap). */
  conflicts: { report: UsageReportJson; stored: Hex }[];
  /** The enclave signer allowed to read the stored reports; taken from the first evidence bundle when unset. */
  signer?: string;
  /** The usage domain (feeSplitter, chainId) the usageHash is computed in; taken from the first evidence bundle when unset. */
  domain?: ReturnType<typeof usageDomain>;
  /** While true, every request fails with 503 (an outage, or a customer firewall in front of the platform). */
  down: boolean;
  /** Answer health reports with `reattest: true`. */
  reattest: boolean;
  /** Signed reads seen (for assertions). */
  reads: number;
}

export async function startFakePlatform(o: { pageSize?: number; now?: () => number } = {}): Promise<FakePlatform> {
  const rec: Omit<FakePlatform, keyof TestServer> = {
    evidence: [],
    usage: [],
    health: [],
    failEvidence: 0,
    stored: [],
    conflicts: [],
    down: false,
    reattest: false,
    reads: 0,
  };
  const pageSize = o.pageSize ?? 500;
  const server = await serve(async (req, body) => {
    if (rec.down) return { status: 503, body: { error: { code: "internal", message: "down" } } };
    const json = body ? JSON.parse(body) : undefined;
    const url = new URL(req.url ?? "/", "http://platform");
    if (req.method === "POST" && url.pathname === "/v1/evidence") {
      if (rec.failEvidence > 0) {
        rec.failEvidence--;
        return { status: 503, body: { error: "oracle busy" } };
      }
      rec.evidence.push(json);
      const b = json as EvidenceBundle;
      rec.signer ??= b.enclaveSigner.toLowerCase();
      rec.domain ??= usageDomain(b.config.contracts.feeSplitter as Hex, b.chainId);
      return { status: 200, body: { deploymentId: json.deploymentId, txHash: `0x${"ab".repeat(32)}`, kind: rec.evidence.length === 1 ? "register" : "heartbeat" } };
    }
    if (req.method === "POST" && url.pathname === "/v1/usage") {
      rec.usage.push(json);
      const report = json.report as UsageReportJson;
      const usageHash = rec.domain ? usageReportDigest(usageReportFromJson(report), rec.domain).toLowerCase() as Hex : (`0x${String(rec.usage.length).padStart(64, "0")}` as Hex);
      const same = rec.stored.find((r) => r.usageHash === usageHash);
      if (same) return { status: 200, body: { usageHash, accepted: true, duplicate: true } };
      const overlap = rec.stored.find((r) => r.report.deploymentId.toLowerCase() === report.deploymentId.toLowerCase() && periodsOverlap(r, report));
      if (overlap) {
        rec.conflicts.push({ report, stored: overlap.usageHash });
        return {
          status: 409,
          body: { error: { code: "conflict", message: "This usage report overlaps a period that was already reported.", detail: { usageHash: overlap.usageHash, periodStart: overlap.periodStart, periodEnd: overlap.periodEnd } } },
        };
      }
      rec.stored.push({ usageHash, periodStart: report.periodStart, periodEnd: report.periodEnd, report, signature: json.signature, receivedAt: o.now?.() ?? Math.floor(Date.now() / 1000) });
      rec.stored.sort((a, b) => a.periodStart - b.periodStart || (a.usageHash < b.usageHash ? -1 : 1));
      return { status: 200, body: { usageHash, accepted: true, duplicate: false } };
    }
    if (req.method === "POST" && url.pathname === "/v1/health") {
      rec.health.push(json);
      return { status: 200, body: { ok: true, ...(rec.reattest ? { reattest: true } : {}) } };
    }
    const m = /^\/v1\/deployments\/(0x[0-9a-f]{64})\/usage-reports$/.exec(url.pathname);
    if (req.method === "GET" && m) {
      const id = m[1] as Hex;
      if (!rec.signer) return { status: 404, body: { error: { code: "not_found", message: "This deployment is not registered." } } };
      const at = Number(req.headers["x-sealed-at"]);
      const sig = req.headers["x-sealed-signature"];
      if (typeof sig !== "string" || !Number.isSafeInteger(at)) return { status: 401, body: { error: { code: "signature_invalid", message: "A signed read needs x-sealed-at and x-sealed-signature." } } };
      const signer = await recoverCjsonBodySigner(usageReportsReadMessage(id, at), sig as Hex).catch(() => "");
      if (signer !== rec.signer) return { status: 401, body: { error: { code: "signature_invalid", message: "The read is not signed by this deployment's enclave signer." } } };
      rec.reads++;
      const after = url.searchParams.get("after");
      const limit = Math.min(pageSize, Number(url.searchParams.get("limit") ?? pageSize));
      const key = (r: StoredReport) => `${String(r.periodStart).padStart(20, "0")}:${r.usageHash}`;
      const from = after ? `${after.split(":")[0]?.padStart(20, "0")}:${after.split(":")[1]}` : "";
      const rows = rec.stored.filter((r) => r.report.deploymentId.toLowerCase() === id && key(r) > from);
      const page = rows.slice(0, limit);
      const last = page.at(-1);
      return { status: 200, body: { deploymentId: id, reports: page, next: rows.length > limit && last ? `${last.periodStart}:${last.usageHash}` : null } };
    }
    return { status: 404, body: { error: { code: "not_found", message: "Not found." } } };
  });
  return Object.assign(rec, server);
}
