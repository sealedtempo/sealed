import { encodeAbiParameters, keccak256, toBytes } from "viem";
import { describe, expect, it } from "vitest";
import { sha256Hex, appId, deploymentId, eventLogHash, imageId, measurementsHash, releaseId, stackHash } from "../src/ids.js";

describe("ids and hashes (INTERFACES 2)", () => {
  it("appId = keccak256(slug)", () => {
    expect(appId("llm-gateway")).toBe(keccak256(toBytes("llm-gateway")));
  });
  it("releaseId, deploymentId and imageId use abi.encode", () => {
    const a = appId("crm");
    const bundle = `0x${"ab".repeat(32)}` as const;
    expect(releaseId(a, "1.0.0", bundle)).toBe(
      keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "string" }, { type: "bytes32" }], [a, "1.0.0", bundle])),
    );
    const customer = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";
    const stack = `0x${"11".repeat(32)}` as const;
    const salt = `0x${"22".repeat(32)}` as const;
    expect(deploymentId(customer, stack, salt)).toBe(deploymentId(customer.toLowerCase() as `0x${string}`, stack, salt));
    const mh = measurementsHash(`0x${"11".repeat(48)}`, `0x${"22".repeat(48)}`, `0x${"33".repeat(48)}`, `0x${"44".repeat(48)}`);
    expect(mh).toBe(keccak256(`0x${"11".repeat(48)}${"22".repeat(48)}${"33".repeat(48)}${"44".repeat(48)}`));
    expect(imageId("sealed-sim", "1", mh)).toMatch(/^0x[0-9a-f]{64}$/);
  });
  it("measurementsHash requires 48-byte registers", () => {
    expect(() => measurementsHash("0x11", "0x22", "0x33", "0x44")).toThrow("48 bytes");
  });
  it("stackHash matches the dstack golden sample compose", () => {
    const compose =
      '{"allowed_envs":[],"docker_compose_file":"services:\\n  web:\\n    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000\\n","gateway_enabled":false,"key_provider":"none","kms_enabled":false,"manifest_version":2,"name":"hello","no_instance_id":false,"public_logs":true,"public_sysinfo":true,"public_tcbinfo":true,"runner":"docker-compose","secure_time":false,"storage_fs":"ext4"}';
    expect(stackHash(compose)).toBe("0xa06cf4774c792a56cdb756e773d0acf5d508332376982dc8a1e70811d33377e4");
  });
  it("eventLogHash is sha256 of the CJSON array", () => {
    expect(eventLogHash([{ b: 1, a: "x" }])).toBe(sha256Hex('[{"a":"x","b":1}]'));
  });
});
