import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// RUN instructions with comment lines dropped and continuation lines joined, as BuildKit reads them.
const runInstructions = (dockerfileText: string) =>
  dockerfileText.split("\n").filter((l) => !l.trimStart().startsWith("#")).join("\n").replace(/\\\n/g, " ").split("\n").filter((l) => /^RUN\s/.test(l));

const text = readFileSync(join(import.meta.dirname, "..", "Dockerfile"), "utf8");

describe("runtime/agent/Dockerfile", () => {
  // images-preflight: pnpm writes the install time into node_modules/.modules.yaml (prunedAt) and
  // .pnpm-workspace-state-v1.json (lastValidatedTimestamp). Shipped in the image, they gave every
  // build a new digest, so the runtime image workflow's no-cache rebuild check (exit 4) failed.
  it("drops the pnpm metadata that records the install time", () => {
    const runs = runInstructions(text);
    const deploy = runs.filter((r) => /pnpm .*deploy .*--prod|pnpm .*--prod .*deploy/.test(r));
    expect(deploy).toHaveLength(1);
    const run = deploy[0]!;
    const rm = run.indexOf("rm -f /out/node_modules/.modules.yaml /out/node_modules/.pnpm-workspace-state*.json");
    expect(rm).toBeGreaterThan(run.search(/pnpm [^&]*deploy/));
  });

  // images-preflight: apt, dpkg and ldconfig write the build time (or inode times) into their logs
  // and ldconfig's aux-cache; shipped in the runtime stage they gave every build a new digest.
  it("removes the apt, dpkg and ldconfig files that record the build time", () => {
    const runtime = text.slice(text.indexOf("AS runtime"));
    const runs = runInstructions(runtime).filter((l) => /apt-get install/.test(l));
    expect(runs).toHaveLength(1);
    const run = runs[0]!;
    const install = run.indexOf("apt-get install");
    for (const f of ["/var/log/dpkg.log", "/var/log/apt", "/var/log/alternatives.log", "/var/cache/ldconfig/aux-cache", "/var/cache/debconf/*-old", "/var/lib/dpkg/*-old"]) {
      expect(run.indexOf(f), f).toBeGreaterThan(install);
    }
  });

  it("pins the node base image by digest", () => {
    expect(text).toMatch(/^ARG NODE_IMAGE=node:[^@\s]+@sha256:[0-9a-f]{64}$/m);
    for (const l of text.split("\n").filter((x) => /^FROM\s/.test(x))) expect(l).toMatch(/^FROM \$\{NODE_IMAGE\} AS \w+$/);
  });
});
