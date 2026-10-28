// The devnet's sealed-agent process: the real Agent class from runtime/agent (its build) with the real key broker
// client, platform client, dstack client and Tempo fee payer, booted exactly as src/main.ts boots it. Only what a
// laptop has no equivalent for is replaced, and nothing here is part of the agent image:
//   - the block-device tools behind LuksDisk (FakeLuksRunner: the LUKS2 format, open and mount steps still run),
//   - Caddy's admin socket (switches are recorded in a file),
//   - Caddy itself for /attest: with DEVNET_TLS_TARGET the agent reads the served key from the devnet's TLS front
//     (src/attestFront.ts) exactly as it reads Caddy's, by a TLS handshake; otherwise a fixed key,
//   - egress stats and container health probes (no containers run),
//   - the caller address of local API calls: apps post usage from their fixed 172.30.x.y addresses, which this
//     host takes from the x-devnet-peer header,
//   - name resolution of the measured config's endpoints: the composer refuses loopback and private IP endpoints,
//     so the devnet config names <service>.devnet.test hosts (RFC 6761), which this process resolves to 127.0.0.1
//     (inside a VM sealed-egress answers DNS for the allowed names),
//   - chown of the data-disk volume directories (recorded; the agent is not root here).
//
// Environment: everything settingsFromEnv reads (SEALED_DEV_SIM=1 required), plus DEVNET_LUKS_STATE,
// DEVNET_MOUNTINFO, DEVNET_OUT (directory for ready.json, evidence.json, caddy.log, chown.log).
import dns from "node:dns";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import type http from "node:http";
import { join } from "node:path";
import { Agent } from "@sealed/agent/dist/src/agent.js";
import { LuksDisk } from "@sealed/agent/dist/src/disk.js";
import { createLogger, errorFields } from "@sealed/agent/dist/src/log.js";
import { settingsFromEnv } from "@sealed/agent/dist/src/settings.js";
import { normalizePeer } from "@sealed/agent/dist/src/stack.js";
import { readFileSync } from "node:fs";
import { fixedTlsKey, ServedCertSource, type TlsKeySource } from "@sealed/agent/dist/src/tls.js";
import { FakeLuksRunner } from "./fakeLuks.ts";

export const PEER_HEADER = "x-devnet-peer";
export const DEVICE_ID = "253:7";
export const DEVNET_DOMAIN = ".devnet.test";

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void;

/** Resolves every *.devnet.test name to 127.0.0.1 for this process (node:http and fetch both use dns.lookup). */
export function installDevnetResolver(): void {
  const original = dns.lookup;
  const patched = (host: string, opts: unknown, cb?: LookupCallback) => {
    const callback = (typeof opts === "function" ? opts : cb) as LookupCallback;
    const options = (typeof opts === "object" && opts !== null ? opts : {}) as dns.LookupOptions;
    if (typeof host === "string" && host.endsWith(DEVNET_DOMAIN)) {
      if (options.all) process.nextTick(callback, null, [{ address: "127.0.0.1", family: 4 }]);
      else process.nextTick(callback, null, "127.0.0.1", 4);
      return;
    }
    return (original as (...a: unknown[]) => void).call(dns, host, opts, cb);
  };
  (dns as { lookup: unknown }).lookup = patched;
}

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

const writeJson = (path: string, v: unknown) => writeFileSync(path, `${JSON.stringify(v, null, 2)}\n`);

async function main(): Promise<void> {
  installDevnetResolver();
  const log = createLogger({ svc: "sealed-agent" });
  const settings = settingsFromEnv(process.env);
  if (!settings.devSim) throw new Error("the devnet agent host runs only with SEALED_DEV_SIM=1");
  const out = need("DEVNET_OUT");
  mkdirSync(out, { recursive: true });
  const mountInfoPath = need("DEVNET_MOUNTINFO");
  let tls: TlsKeySource = fixedTlsKey(`0x${"77".repeat(32)}`);
  const front = process.env.DEVNET_TLS_TARGET;
  if (front) {
    const [host, port] = front.split(":");
    const attestHost = (JSON.parse(readFileSync(settings.stackPath ?? "", "utf8")) as { attestHost: string }).attestHost;
    tls = new ServedCertSource({ host: host as string, port: Number(port) }, attestHost);
  }
  // DEVNET_SAME_BOOT=1: an agent (container) restart inside one boot keeps the dm mapping and the mount.
  const runner = new FakeLuksRunner({ statePath: need("DEVNET_LUKS_STATE"), device: settings.dataDevice, mountInfoPath, deviceId: DEVICE_ID, newBoot: process.env.DEVNET_SAME_BOOT !== "1" });
  const agent = new Agent({
    settings,
    log,
    disk: new LuksDisk({ device: settings.dataDevice, name: settings.luksName, mountPoint: settings.dataMount, runner, mountInfoPath, deviceId: async () => DEVICE_ID, log }),
    caddy: { apply: async (variant) => appendFileSync(join(out, "caddy.log"), `${Math.floor(Date.now() / 1000)} ${variant}\n`) },
    tls,
    egressStats: async () => undefined,
    probe: async () => false,
    chown: async (path, uid, gid) => appendFileSync(join(out, "chown.log"), `${uid}:${gid} ${path}\n`),
    peerOf: (req: http.IncomingMessage) => {
      const h = req.headers[PEER_HEADER];
      return typeof h === "string" ? h : normalizePeer(req.socket.remoteAddress);
    },
    releaseDeniedDelayMs: Number(process.env.DEVNET_DENIED_DELAY_MS ?? 2000),
  });
  const shutdown = (sig: string) => {
    log.info("shutting down", { signal: sig });
    void agent.stop().then(() => process.exit(0));
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  await agent.boot();
  agent.start();
  writeJson(join(out, "ready.json"), {
    deploymentId: agent.ctx?.deploymentId,
    stackHash: agent.ctx?.stackHash,
    enclaveSigner: agent.enclaveSigner,
    port: agent.port,
    disk: runner.state.ops,
  });
  const evidence = agent.evidence;
  if (evidence) {
    void evidence.then(
      (result) => writeJson(join(out, "evidence.json"), { result, bundle: agent.lastEvidence }),
      (err) => writeJson(join(out, "evidence-error.json"), errorFields(err)),
    );
  }
}

main().catch((err) => {
  process.stderr.write(`agent host: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exit(1);
});
