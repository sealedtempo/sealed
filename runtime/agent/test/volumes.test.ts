import { mkdir, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseStackInfo } from "../src/stack.js";
import { createVolumeDirs, volumeDirsFromAppCompose, volumeDirsFromStack } from "../src/volumes.js";
import { makeAppCompose, makeConfig, makeStackInfo } from "./helpers/fixtures.js";

/** sealed-stack/v1 for the fixture config with dataDirs and one declared owner (brief item 11). */
function stackWithOwners(over: { owner?: string; dataDirs?: string[]; volumePath?: string } = {}) {
  const config = makeConfig();
  const stack = makeStackInfo(config) as ReturnType<typeof makeStackInfo> & Record<string, unknown>;
  const crm = stack.apps[0] as Record<string, unknown>;
  crm.volumes = [
    { name: "db", path: over.volumePath ?? "/mnt/sealed-data/crm/db", owner: over.owner ?? "999:998" },
    { name: "files", path: "/mnt/sealed-data/crm/files" },
  ];
  stack.dataRoot = "/mnt/sealed-data";
  stack.dataDirs = over.dataDirs ?? ["/mnt/sealed-data/_caddy/data", "/mnt/sealed-data/crm/db", "/mnt/sealed-data/crm/files"];
  return parseStackInfo(JSON.stringify(stack));
}

describe("per-app volume directories", () => {
  it("finds bind sources under the data root only", () => {
    const dirs = volumeDirsFromAppCompose(makeAppCompose(makeConfig()), "/mnt/sealed-data");
    expect(dirs).toEqual([
      { path: "/mnt/sealed-data/crm/db" },
      { path: "/mnt/sealed-data/crm/files", uid: 1000, gid: 1000 },
    ]);
  });
  it("maps the compose's host paths onto where the agent sees the data disk", () => {
    const dirs = volumeDirsFromAppCompose(makeAppCompose(makeConfig()), "/mnt/sealed-data", "/tmp/x/data");
    expect(dirs.map((d) => d.path)).toEqual(["/tmp/x/data/crm/db", "/tmp/x/data/crm/files"]);
  });
  it("ignores escapes and malformed composes", () => {
    const compose = JSON.stringify({ docker_compose_file: JSON.stringify({ services: { a: { volumes: ["/mnt/sealed-data/../etc:/x", "/mnt/sealed-data:/y", "named:/z"] } } }) });
    expect(volumeDirsFromAppCompose(compose, "/mnt/sealed-data")).toEqual([]);
    expect(volumeDirsFromAppCompose(JSON.stringify({ docker_compose_file: "not json" }), "/mnt/sealed-data")).toEqual([]);
  });
  it("creates the directories", async () => {
    const root = await mkdtemp(join(tmpdir(), "sealed-vol-"));
    try {
      await createVolumeDirs(volumeDirsFromAppCompose(makeAppCompose(makeConfig()), "/mnt/sealed-data", root));
      expect((await stat(join(root, "crm", "db"))).isDirectory()).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("adds sealed-stack dataDirs and enforces the owners the manifests declare", () => {
    const dirs = volumeDirsFromStack(stackWithOwners(), makeAppCompose(makeConfig()), "/tmp/x/data");
    expect(dirs).toEqual([
      { path: "/tmp/x/data/_caddy/data" },
      { path: "/tmp/x/data/crm/db", uid: 999, gid: 998, declared: true },
      // No declared owner: the guess from crm-server's user stays a creation-time default.
      { path: "/tmp/x/data/crm/files", uid: 1000, gid: 1000 },
    ]);
  });
  it("refuses stack paths outside the data root or outside the app's own directory", () => {
    expect(() => volumeDirsFromStack(stackWithOwners({ dataDirs: ["/etc"] }), makeAppCompose(makeConfig()), "/x")).toThrow("not below");
    expect(() => volumeDirsFromStack(stackWithOwners({ volumePath: "/mnt/sealed-data/llm-gateway/db" }), makeAppCompose(makeConfig()), "/x")).toThrow("outside");
    expect(() => parseStackInfo(JSON.stringify({ ...makeStackInfo(makeConfig()), apps: [{ ...makeStackInfo(makeConfig()).apps[0], volumes: [{ name: "db", path: "/mnt/sealed-data/crm/db", owner: "root" }] }] }))).toThrow("owner");
    expect(() => parseStackInfo(JSON.stringify({ ...makeStackInfo(makeConfig()), apps: [{ ...makeStackInfo(makeConfig()).apps[0], volumes: [{ name: "db", path: "/mnt/sealed-data/crm/db", owner: "4294967295:0" }] }] }))).toThrow("2^31");
  });
  it("chowns declared owners on every boot and guessed owners only on creation", async () => {
    const root = await mkdtemp(join(tmpdir(), "sealed-vol-"));
    try {
      const calls: string[] = [];
      const chownFn = async (p: string, uid: number, gid: number) => {
        calls.push(`${p.slice(root.length + 1)}=${uid}:${gid}`);
      };
      const dirs = volumeDirsFromStack(stackWithOwners(), makeAppCompose(makeConfig()), root);
      await createVolumeDirs(dirs, { chownFn });
      expect(calls).toEqual(["crm/db=999:998", "crm/files=1000:1000"]);
      calls.length = 0;
      await createVolumeDirs(dirs, { chownFn });
      expect(calls).toEqual(["crm/db=999:998"]);
      expect((await stat(join(root, "_caddy", "data"))).isDirectory()).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it("refuses a symlink or a file where a volume directory belongs", async () => {
    const root = await mkdtemp(join(tmpdir(), "sealed-vol-"));
    try {
      await mkdir(join(root, "crm"), { recursive: true });
      await symlink("/etc", join(root, "crm", "db"));
      await expect(createVolumeDirs([{ path: join(root, "crm", "db"), uid: 1, gid: 1, declared: true }], { chownFn: async () => undefined })).rejects.toThrow("not a directory");
      await writeFile(join(root, "crm", "files"), "x");
      await expect(createVolumeDirs([{ path: join(root, "crm", "files") }])).rejects.toThrow("not a directory");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
