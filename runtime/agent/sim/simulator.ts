// dstack-compatible guest agent simulator (INTERFACES 15). Serves the v0 subset sealed-agent uses
// (POST /GetQuote, GET /Info, GET /Version) over a unix socket or TCP. Quotes are the clearly
// marked SEALEDSIM1 format; production verifiers reject them.
import { readFile, rm } from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  bytesToBareHex,
  encodeSimQuote,
  hexToBytes,
  replayRtmr3,
  sealedEventLog,
  sha256Hex,
  simMeasurements,
} from "@sealed/core";

export const SIM_VERSION = "sealed-dstack-sim/0.1.0";

export interface SimulatorOptions {
  /** Exact app-compose.json text (read from appComposePath when not given). */
  appCompose?: string;
  appComposePath?: string;
  /** Use the debug image measurements (mrtd 0x55..) and set debug: true in quotes. */
  debug?: boolean;
}

export interface SimulatorState {
  appCompose: string;
  composeHash: string;
  eventLog: ReturnType<typeof sealedEventLog>;
  rtmr3: string;
  debug: boolean;
}

export async function loadSimulatorState(opts: SimulatorOptions): Promise<SimulatorState> {
  const appCompose = opts.appCompose ?? (opts.appComposePath ? await readFile(opts.appComposePath, "utf8") : undefined);
  if (appCompose === undefined) throw new Error("simulator needs an app-compose.json");
  const eventLog = sealedEventLog({ appCompose });
  return {
    appCompose,
    composeHash: sha256Hex(appCompose).slice(2),
    eventLog,
    rtmr3: bytesToBareHex(replayRtmr3(eventLog)),
    debug: opts.debug ?? false,
  };
}

/** Right-pads report_data to 64 bytes; more than 64 bytes is an error, as in dstack's pad64. */
export function padReportData(hex: string): Uint8Array {
  const bytes = hexToBytes(hex);
  if (bytes.length > 64) throw new Error("report_data is longer than 64 bytes");
  const out = new Uint8Array(64);
  out.set(bytes, 0);
  return out;
}

export function quoteFor(state: SimulatorState, reportData: Uint8Array) {
  const m = simMeasurements(state.debug);
  const quote = encodeSimQuote({ ...m, rtmr3: state.rtmr3, reportData: bytesToBareHex(reportData), debug: state.debug });
  return {
    quote: bytesToBareHex(quote),
    event_log: JSON.stringify(state.eventLog),
    report_data: bytesToBareHex(reportData),
    vm_config: "{}",
  };
}

export function infoFor(state: SimulatorState) {
  const m = simMeasurements(state.debug);
  const appId = state.eventLog[1]?.event_payload ?? "";
  const instanceId = state.eventLog[4]?.event_payload ?? "";
  return {
    app_id: appId,
    instance_id: instanceId,
    app_cert: "",
    tcb_info: JSON.stringify({
      mrtd: m.mrtd,
      rtmr0: m.rtmr0,
      rtmr1: m.rtmr1,
      rtmr2: m.rtmr2,
      rtmr3: state.rtmr3,
      event_log: state.eventLog,
      app_compose: state.appCompose,
    }),
    app_name: "sealed-sim",
    device_id: "",
    mr_aggregated: "",
    os_image_hash: "",
    key_provider_info: '{"name":"tpm","id":""}',
    compose_hash: state.composeHash,
    vm_config: "{}",
    cloud_vendor: "sealed-sim",
    cloud_product: "sealed-sim",
  };
}

function send(res: http.ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text) });
  res.end(text);
}

async function readBody(req: http.IncomingMessage, limit = 64 * 1024): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > limit) throw new Error("request too large");
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function createSimulatorServer(state: SimulatorState): http.Server {
  return http.createServer(async (req, res) => {
    const path = (req.url ?? "/").split("?")[0]?.replace(/^\/v0\//, "/") ?? "/";
    try {
      if (path === "/GetQuote" && req.method === "POST") {
        const body = JSON.parse((await readBody(req)) || "{}") as { report_data?: unknown };
        if (typeof body.report_data !== "string") return send(res, 400, { error: "report_data must be a hex string" });
        let rd: Uint8Array;
        try {
          rd = padReportData(body.report_data);
        } catch (err) {
          return send(res, 400, { error: (err as Error).message });
        }
        return send(res, 200, quoteFor(state, rd));
      }
      if (path === "/Info" && req.method === "GET") return send(res, 200, infoFor(state));
      if (path === "/Version" && req.method === "GET") return send(res, 200, { version: SIM_VERSION, rev: "" });
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("Service not found");
    } catch (err) {
      send(res, 400, { error: (err as Error).message });
    }
  });
}

export interface RunningSimulator {
  /** Value for DSTACK_SIMULATOR_ENDPOINT. */
  endpoint: string;
  state: SimulatorState;
  close(): Promise<void>;
}

export async function startSimulator(
  opts: SimulatorOptions & { socket?: string; port?: number; host?: string },
): Promise<RunningSimulator> {
  const state = await loadSimulatorState(opts);
  const server = createSimulatorServer(state);
  let endpoint: string;
  if (opts.socket) {
    await rm(opts.socket, { force: true });
    await new Promise<void>((ok, fail) => server.once("error", fail).listen(opts.socket, () => ok()));
    endpoint = opts.socket;
  } else {
    const host = opts.host ?? "127.0.0.1";
    await new Promise<void>((ok, fail) => server.once("error", fail).listen(opts.port ?? 0, host, () => ok()));
    endpoint = `http://${host}:${(server.address() as AddressInfo).port}`;
  }
  return {
    endpoint,
    state,
    close: () =>
      new Promise<void>((ok) => {
        server.close(() => ok());
        server.closeAllConnections();
      }),
  };
}
