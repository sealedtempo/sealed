// DstackClient against a guest agent that replays the runtime spike's real dstack 0.6.1 answers (GCP C3 TDX,
// verifier/attest/testdata/gcp): the quote the agent hands to the key broker and puts in evidence must be the
// signed quote, not dstack's 8000-byte zero-padded buffer, which the verifier and the broker refuse.
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { bytesToBareHex, eventLogHash, hexToBytes, quoteHash, sha256Hex, verifySealedEventLog } from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DstackClient } from "../src/dstack.js";
import { parseEndpoint } from "../src/http.js";

const gcpDir = join(import.meta.dirname, "../../../verifier/attest/testdata/gcp");
const read = (f: string) => readFileSync(join(gcpDir, f), "utf8");
const expected = JSON.parse(read("expected.json")) as {
  signedQuoteLength: number;
  getQuoteLength: number;
  quoteHash: string;
  eventLogHash: string;
  rtmr3: string;
  composeHash: string;
};
const capture = JSON.parse(read("captures/boot1-getquote1.json")) as { quote: string; event_log: string; report_data: string; vm_config: string };

describe("DstackClient on a real dstack 0.6.1 capture", () => {
  let server: Server;
  let endpoint: string;
  let quoteBody = capture.quote;
  beforeAll(async () => {
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.setHeader("content-type", "application/json");
        if (req.url === "/GetQuote" && JSON.parse(body).report_data === capture.report_data) {
          res.end(JSON.stringify({ ...capture, quote: quoteBody }));
        } else if (req.url === "/Info") {
          res.end(read("info.json"));
        } else {
          res.statusCode = 404;
          res.end("{}");
        }
      });
    });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => new Promise<void>((ok) => server.close(() => ok())));

  it("returns the signed quote without the guest agent's zero padding", async () => {
    quoteBody = capture.quote;
    expect(hexToBytes(capture.quote).length).toBe(expected.getQuoteLength);
    const client = new DstackClient(parseEndpoint(endpoint));
    const q = await client.getQuote(hexToBytes(capture.report_data));
    expect(q.quote.length).toBe(expected.signedQuoteLength);
    expect(bytesToBareHex(q.quote)).toBe(readFileSync(join(gcpDir, "quote.dat")).toString("hex"));
    // The values the Go verifier's TestRealGCPGolden asserts for the same capture.
    expect(quoteHash(q.quote)).toBe(`0x${expected.quoteHash}`);
    expect(eventLogHash(q.eventLog)).toBe(`0x${expected.eventLogHash}`);
    const appCompose = await client.appCompose();
    expect(sha256Hex(appCompose)).toBe(`0x${expected.composeHash}`);
    expect(bytesToBareHex(verifySealedEventLog(q.eventLog, appCompose))).toBe(expected.rtmr3);
  });

  it("refuses a quote with non-zero bytes after the signature data", async () => {
    quoteBody = `${capture.quote.slice(0, -2)}01`;
    try {
      await expect(new DstackClient(parseEndpoint(endpoint)).getQuote(hexToBytes(capture.report_data))).rejects.toThrow("not zero padding");
    } finally {
      quoteBody = capture.quote;
    }
  });
});
