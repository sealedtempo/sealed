import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createVolumeDirs, volumeDirsFromAppCompose } from "../src/volumes.js";
import { makeAppCompose, makeConfig } from "./helpers/fixtures.js";

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
});
