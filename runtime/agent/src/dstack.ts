// Client for the dstack guest agent (v0 API) on /var/run/dstack.sock (DSTACK_SOCKET), or the dev
// simulator (DSTACK_SIMULATOR_ENDPOINT, a unix socket path or http URL, honored only with SEALED_DEV_SIM=1).
import { bytesToBareHex, type DstackEvent, equalBytes, hexToBytes } from "@sealed/core";
import { type Endpoint, localJson, parseEndpoint } from "./http.js";

export const DEFAULT_DSTACK_SOCKET = "/var/run/dstack.sock";

export interface Quote {
  quote: Uint8Array;
  eventLog: DstackEvent[];
  reportData: Uint8Array;
  vmConfig: string;
}

export interface QuoteProvider {
  getQuote(reportData: Uint8Array): Promise<Quote>;
  /** The exact app-compose.json text the CVM booted with. */
  appCompose(): Promise<string>;
}

interface GetQuoteResponse {
  quote: string;
  event_log: string;
  report_data: string;
  vm_config: string;
}

export class DstackClient implements QuoteProvider {
  constructor(private readonly endpoint: Endpoint = parseEndpoint(DEFAULT_DSTACK_SOCKET)) {}

  async getQuote(reportData: Uint8Array): Promise<Quote> {
    if (reportData.length !== 64) throw new Error("report_data must be exactly 64 bytes");
    const res = await localJson<GetQuoteResponse>(this.endpoint, "/GetQuote", {
      body: { report_data: bytesToBareHex(reportData) },
      timeoutMs: 60_000,
    });
    const echoed = hexToBytes(res.report_data);
    if (!equalBytes(echoed, reportData)) throw new Error("guest agent returned a different report_data");
    const eventLog = JSON.parse(res.event_log) as DstackEvent[];
    if (!Array.isArray(eventLog)) throw new Error("event_log is not an array");
    return { quote: hexToBytes(res.quote), eventLog, reportData: echoed, vmConfig: res.vm_config };
  }

  async appCompose(): Promise<string> {
    const info = await localJson<{ tcb_info?: string; app_compose?: string }>(this.endpoint, "/Info");
    if (typeof info.app_compose === "string") return info.app_compose;
    if (typeof info.tcb_info === "string") {
      const tcb = JSON.parse(info.tcb_info) as { app_compose?: unknown };
      if (typeof tcb.app_compose === "string") return tcb.app_compose;
    }
    throw new Error("guest agent Info has no app_compose (public_tcbinfo must be true)");
  }
}
