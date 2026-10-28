// sealed-stack/v1 parsing: service addresses in the composer 1.1 form (one `ip`) and with per-app
// networks (brief item 4: every address a service owns, `ips`).
import { describe, expect, it } from "vitest";
import { parseStackInfo } from "../src/stack.js";
import { makeConfig, makeStackInfo } from "./helpers/fixtures.js";

const withServices = (services: unknown[]) => {
  const s = makeStackInfo(makeConfig()) as ReturnType<typeof makeStackInfo>;
  (s.apps[0] as { services: unknown[] }).services = services;
  return JSON.stringify(s);
};

describe("sealed-stack/v1 services", () => {
  it("normalizes ip and ips to every address of the service", () => {
    const one = parseStackInfo(withServices([{ name: "crm-server", ip: "172.30.0.16", primary: true }]));
    expect(one.apps[0]?.services[0]).toMatchObject({ ip: "172.30.0.16", ips: ["172.30.0.16"] });
    const many = parseStackInfo(withServices([{ name: "crm-server", ips: ["172.30.0.16", "172.30.1.16"], primary: true }]));
    expect(many.apps[0]?.services[0]).toMatchObject({ ip: "172.30.0.16", ips: ["172.30.0.16", "172.30.1.16"] });
    const both = parseStackInfo(withServices([{ name: "crm-server", ip: "172.30.1.16", ips: ["172.30.0.16", "172.30.1.16"], primary: true }]));
    expect(both.apps[0]?.services[0]?.ips).toEqual(["172.30.1.16", "172.30.0.16"]);
  });
  it("refuses a service without an address or with a malformed one", () => {
    expect(() => parseStackInfo(withServices([{ name: "crm-server", primary: true }]))).toThrow("ip or ips");
    expect(() => parseStackInfo(withServices([{ name: "crm-server", ips: ["300.1.1.1"], primary: true }]))).toThrow("IPv4");
  });
});
