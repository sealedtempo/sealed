// A minimal sealed-agent boot (spec 5.6 steps 1-2) written only with @sealed/core, the library the TypeScript agent
// uses: fresh X25519 key, GET /v1/nonce, kb-release report_data, the dstack simulator's event log and quote,
// POST /v1/release, HPKE open and schema checks. Run by TestCoreAgentReleasesFromGoBroker against the Go broker.
// Usage: node core-agent-release.mjs <path to packages/core/dist/index.js> <broker URL> <stack.json>
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [corePath, broker, stackPath] = process.argv.slice(2);
const core = await import(pathToFileURL(corePath).href);
const stack = JSON.parse(readFileSync(stackPath, "utf8"));

const kp = await core.generateKeyPair();
const nonceResp = core.nonceResponseSchema.parse(await (await fetch(`${broker}/v1/nonce`)).json());
const nonce = core.hexToBytes(nonceResp.nonce, 32);
const reportData = core.kbReleaseReportData(nonce, kp.publicKey);
const eventLog = core.sealedEventLog({ appCompose: stack.appCompose });
const rtmr3 = core.verifySealedEventLog(eventLog, stack.appCompose);
const quote = core.encodeSimQuote({
  ...core.simMeasurements(false),
  rtmr3: core.bytesToBareHex(rtmr3),
  reportData: core.bytesToBareHex(reportData),
  debug: false,
});
const req = core.releaseRequestSchema.parse({
  nonce: nonceResp.nonce,
  ephemeralPub: core.bytesToHex(kp.publicKey),
  quote: core.bytesToHex(quote),
  eventLog,
  config: stack.config,
  appCompose: stack.appCompose,
  releaseIds: stack.releaseIds,
  imageId: stack.imageId,
});
const resp = await fetch(`${broker}/v1/release`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(req) });
const json = await resp.json();
if (resp.status !== 200) {
  core.denialSchema.parse(json);
  console.log(JSON.stringify({ status: resp.status, denial: json }));
  process.exit(0);
}
const body = core.releaseResponseSchema.parse(json);
const pt = await core.openKbRelease(kp.privateKey, nonce, core.hexToBytes(body.enc, 32), core.hexToBytes(body.ciphertext));
const text = new TextDecoder().decode(pt);
const payload = core.releasePlaintextSchema.parse(core.parseCJSON(text));
console.log(
  JSON.stringify({
    status: 200,
    stackHash: body.stackHash,
    deploymentId: body.deploymentId,
    expectedDeploymentId: core.deploymentId(stack.config.customer, core.stackHash(stack.appCompose), stack.config.salt),
    secrets: payload.secrets,
    diskKey: payload.diskKey,
    signer: core.enclaveSignerAddress(payload.signerSeed),
    canonical: core.canonicalize(core.parseCJSON(text)) === text,
  }),
);
