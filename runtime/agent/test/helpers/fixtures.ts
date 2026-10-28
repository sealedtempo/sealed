// Shared test fixtures: a public config and an app-compose.json built the way the composer does.
import { canonicalize, type Hex } from "@sealed/core";

export const CUSTOMER = "0x90f79bf6eb2c4f870365e785982e1f101e93b906";

export interface ConfigOverrides {
  customer?: string;
  endpoints?: Record<string, string>;
  contracts?: Record<string, string>;
  settlement?: Record<string, unknown>;
  chainId?: number;
  imageId?: Hex;
  apps?: { id: string; releaseId: Hex }[];
  feeToken?: string;
}

export function makeConfig(o: ConfigOverrides = {}) {
  return {
    schema: "sealed-config/v1",
    chainId: o.chainId ?? 4217,
    customer: o.customer ?? CUSTOMER,
    salt: `0x${"5a".repeat(32)}`,
    imageId: o.imageId ?? `0x${"1d".repeat(32)}`,
    composerVersion: "1.0.0",
    apps: o.apps ?? [
      { id: "crm", releaseId: `0x${"c1".repeat(32)}` },
      { id: "llm-gateway", releaseId: `0x${"11".repeat(32)}` },
    ],
    hostnames: { scheme: "sslip", ip: "34.1.2.3" },
    egressAdditions: {},
    allowedVpcRanges: [],
    endpoints: {
      keyBroker: "http://127.0.0.1:9",
      platformApi: "http://127.0.0.1:9",
      tempoRpc: "http://127.0.0.1:9",
      ...o.endpoints,
    },
    contracts: {
      platformRegistry: `0x${"01".repeat(20)}`,
      appRegistry: `0x${"02".repeat(20)}`,
      deploymentRegistry: `0x${"03".repeat(20)}`,
      feeSplitter: `0x${"04".repeat(20)}`,
      ...o.contracts,
    },
    feeToken: o.feeToken ?? "0x20c0000000000000000000000000000000000000",
    settlement: { mode: "access-key", intervalMinutes: 60, gracePeriodMinutes: 1440, spendLimitPerDay: "2000000", ...o.settlement },
  };
}

/** app-compose.json in the INTERFACES 6 shape, with bind mounts on the data disk. */
export function makeAppCompose(config: unknown, dataMount: string): string {
  const compose = {
    configs: { "sealed-config": { content: canonicalize(config) } },
    services: {
      "crm-server": {
        image: `ghcr.io/sealed-dev/twenty@sha256:${"00".repeat(32)}`,
        user: "1000:1000",
        volumes: [{ type: "bind", source: `${dataMount}/crm/files`, target: "/app/files" }],
      },
      "crm-db": {
        image: `ghcr.io/sealed-dev/postgres@sha256:${"00".repeat(32)}`,
        volumes: [`${dataMount}/crm/db:/var/lib/postgresql/data`, "/etc/passwd:/etc/passwd:ro"],
      },
      "sealed-agent": { image: `ghcr.io/sealed-dev/sealed-agent@sha256:${"00".repeat(32)}` },
    },
  };
  return canonicalize({
    allowed_envs: [],
    docker_compose_file: canonicalize(compose),
    gateway_enabled: false,
    key_provider: "tpm",
    key_provider_id: "",
    kms_enabled: false,
    local_key_provider_enabled: false,
    manifest_version: 2,
    name: "sealed-12345678",
    no_instance_id: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: true,
    runner: "docker-compose",
    secure_time: false,
    storage_fs: "ext4",
  });
}
