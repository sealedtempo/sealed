import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import { findExcluded, normalize } from "../tools/check-image-paths.mjs";

const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const imageDir = join(appDir, "images/tooljet-ce");
const dockerfile = readFileSync(join(imageDir, "Dockerfile"), "utf8");
const entrypoint = readFileSync(join(imageDir, "sealed-entrypoint.sh"), "utf8");
const manifest = parse(readFileSync(join(appDir, "manifest.yaml"), "utf8"));
const fragment = parse(readFileSync(join(appDir, "compose.fragment.yaml"), "utf8"));

describe("derived ToolJet image", () => {
  test("starts from the upstream CE image by digest and ends flattened on scratch", () => {
    const froms = [...dockerfile.matchAll(/^FROM (\S+)/gm)].map((m) => m[1]);
    assert.deepEqual(froms, [
      "docker.io/tooljet/tooljet-ce@sha256:46d1c621efe69c490884cf17d60fbf5c58a9ec3dc57e37432cfd426a11593f47",
      "scratch",
    ]);
    assert.match(dockerfile, /^COPY --from=upstream \/ \/$/m);
    assert.doesNotMatch(dockerfile, /:latest|ee-lts/);
  });

  test("the build fails on Redis modules and configuration left behind", async () => {
    // The find predicate of the RUN step, rooted in a scratch tree instead of /.
    const m = /if find \/ -xdev (\\\(.*?\\\)) -print/s.exec(dockerfile);
    assert.ok(m, "find predicate not found");
    const root = await mkdtemp(join(tmpdir(), "tooljet-tree-"));
    try {
      const predicate = m[1].replace(/\\\n\s*/g, " ").replaceAll("-path '/", `-path '${root}/`);
      const files = {
        "usr/lib/redis/modules/redisearch.so": true,
        "etc/redis/redis.conf": true,
        "opt/vendor/libredisbloom.so": true,
        "usr/bin/redis-server": true,
        "opt/oracle/instantclient_21_10/libclntsh.so.21.1": true,
        "app/server/node_modules/ioredis/built/index.js": false,
        "usr/lib/x86_64-linux-gnu/libssl.so.3": false,
        "usr/local/bin/node": false,
      };
      for (const path of Object.keys(files)) {
        await mkdir(join(root, dirname(path)), { recursive: true });
        await writeFile(join(root, path), "");
      }
      const res = spawnSync("sh", ["-c", `find "${root}" -xdev ${predicate} -print`], { encoding: "utf8" });
      assert.equal(res.status, 0, res.stderr);
      const hits = new Set(res.stdout.trim().split("\n").map((p) => p.slice(root.length + 1)));
      for (const [path, forbidden] of Object.entries(files)) {
        assert.equal([...hits].some((h) => h === path || path.startsWith(`${h}/`)), forbidden, path);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("the build fails on ToolJet enterprise (ee) paths under /app, not on third-party locale data", async () => {
    // The find of the second check, rooted in a scratch tree instead of /app.
    const m = /if find \/app -xdev (.*?) -print \| grep -q \.; then/.exec(dockerfile);
    assert.ok(m, "ee find not found");
    assert.match(dockerfile, /ToolJet enterprise \(ee\) paths in the image/);
    const root = await mkdtemp(join(tmpdir(), "tooljet-app-"));
    try {
      const predicate = m[1];
      const cases = {
        "server/ee/index.js": true,
        "frontend/build/ee/main.js": true,
        "server/dist/src/modules/ee/x.js": true,
        "server/dist/ee": true,
        "server/dist/src/main.js": false,
        "server/eeprom.txt": false,
        "frontend/build/assets/free/x.svg": false,
        "server/node_modules/cldr-data/main/ee/numbers.json": false,
        "plugins/node_modules/x/ee": false,
      };
      for (const [path, forbidden] of Object.entries(cases)) {
        const dir = join(root, `case-${Object.keys(cases).indexOf(path)}`);
        await mkdir(join(dir, dirname(path)), { recursive: true });
        await writeFile(join(dir, path), "");
        const res = spawnSync("sh", ["-c", `find "${dir}" -xdev ${predicate} -print`], { encoding: "utf8" });
        assert.equal(res.status, 0, res.stderr);
        assert.equal(res.stdout.trim() !== "", forbidden, path);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("removes Redis and Oracle Instant Client and fails the build if any is left", () => {
    assert.match(dockerfile, /apt-get purge -y --auto-remove redis-server redis-tools/);
    assert.match(dockerfile, /\/etc\/redis \/usr\/lib\/redis /);
    assert.match(dockerfile, /rm -rf \/opt\/oracle /);
    assert.match(dockerfile, /forbidden binaries left in the image/);
    assert.doesNotMatch(dockerfile, /LD_LIBRARY_PATH/);
    assert.match(dockerfile, /test "\$\(cat \/app\/server\/\.version\)" = "3\.20\.251-lts"/);
  });

  test("runs as uid 1000 with the entrypoint and command the fragment uses", () => {
    assert.match(dockerfile, /test "\$\(id -u appuser\)" = "1000"/);
    assert.match(dockerfile, /^USER appuser$/m);
    assert.match(dockerfile, /^ENTRYPOINT \["\/app\/server\/sealed-entrypoint\.sh"\]$/m);
    assert.match(dockerfile, /^CMD \["node", "dist\/src\/main"\]$/m);
    const server = fragment.services["internal-tools-server"];
    assert.equal(server.user, "1000:1000");
    assert.deepEqual(server.command, ["node", "dist/src/main"]);
  });

  test("the entrypoint runs the database setup and never starts Redis", () => {
    assert.match(entrypoint, /npm run db:setup:prod/);
    assert.match(entrypoint, /exec "\$@"/);
    assert.doesNotMatch(entrypoint.replace(/^#.*$/gm, ""), /redis/i);
    const res = spawnSync("bash", ["-n", join(imageDir, "sealed-entrypoint.sh")], { encoding: "utf8" });
    assert.equal(res.status, 0, res.stderr);
  });
});

describe("check-image-paths", () => {
  const ex = manifest.license_exclusions;

  test("normalizes tar and absolute paths", () => {
    assert.equal(normalize("./opt/oracle/x"), "opt/oracle/x");
    assert.equal(normalize("/usr/bin/redis-server"), "usr/bin/redis-server");
  });

  test("finds excluded directories and files in a listing like the upstream image", () => {
    const listing = [
      "./", "app/", "app/server/dist/src/main.js", "opt/oracle/", "opt/oracle/instantclient_21_10/libclntsh.so.21.1",
      "usr/bin/redis-server", "usr/bin/redis-cli", "usr/local/bin/valkey-server", "app/server/ee/index.js",
      "usr/lib/redis/modules/rejson.so", "etc/redis/redis.conf",
    ];
    assert.deepEqual(findExcluded(listing, ex), [
      "opt/oracle",
      "opt/oracle/instantclient_21_10/libclntsh.so.21.1",
      "usr/bin/redis-server",
      "usr/bin/redis-cli",
      "app/server/ee/index.js",
      "usr/lib/redis/modules/rejson.so",
      "etc/redis/redis.conf",
    ]);
  });

  test("passes a listing of the derived image", () => {
    const listing = ["app/server/dist/src/main.js", "app/server/sealed-entrypoint.sh", "opt/", "usr/bin/node-ish", "app/server/eeprom.txt"];
    assert.deepEqual(findExcluded(listing, ex), []);
  });

  test('"/ee/" matches an ee directory at any depth, outside node_modules and locale data', () => {
    const listing = [
      "app/server/dist/src/modules/ee/license.js", "app/frontend/build/ee/", "app/plugins/ee/x.js", "ee/",
      "app/server/eeprom.txt", "app/frontend/build/assets/free/x.svg", "app/tree/ee.js", "app/server/feeds/",
      "app/server/node_modules/cldr-data/main/ee/numbers.json", "usr/share/locale/ee/LC_MESSAGES/x.mo",
      "app/ee/node_modules/x/index.js",
    ];
    assert.deepEqual(findExcluded(listing, ["/ee/"]), [
      "app/server/dist/src/modules/ee/license.js", "app/frontend/build/ee", "app/plugins/ee/x.js", "ee",
      "app/ee/node_modules/x/index.js",
    ]);
    // A multi-segment exclusion stays anchored at the root.
    assert.deepEqual(findExcluded(["srv/app/server/ee/x", "app/server/ee/x"], ["/app/server/ee/"]), ["app/server/ee/x"]);
  });

  // The manifest's "/app/**/ee/" (a composer lint path glob, license audit F6 and F7) under the same rules.
  test('"/app/**/ee/" matches an ee directory at any depth under app/, outside node_modules', () => {
    const listing = [
      "app/server/dist/src/modules/ee/license.js", "app/frontend/build/ee/", "app/ee/x.js", "app/plugins/ee/x.js",
      "ee/x.js", "srv/app/server/ee/x.js", "app/server/eeprom.txt", "app/frontend/build/assets/free/x.svg", "app/tree/ee.js",
      "app/server/node_modules/cldr-data/main/ee/numbers.json", "app/ee/node_modules/x/ee/y.js", "usr/share/locale/ee/LC_MESSAGES/x.mo",
    ];
    assert.deepEqual(findExcluded(listing, ["/app/**/ee/"]), [
      "app/server/dist/src/modules/ee/license.js", "app/frontend/build/ee", "app/ee/x.js", "app/plugins/ee/x.js",
      "app/ee/node_modules/x/ee/y.js",
    ]);
    // "*" stays within one segment.
    assert.deepEqual(findExcluded(["ms-playwright/chromium-1208/chrome", "ms-playwright/firefox-1538/firefox"], ["/ms-playwright/chromium-*/"]), [
      "ms-playwright/chromium-1208/chrome",
    ]);
  });

  test("the CLI reads a listing on stdin and exits 1 on a hit", () => {
    const tool = join(appDir, "tools/check-image-paths.mjs");
    const bad = spawnSync(process.execPath, [tool], { input: "usr/bin/redis-server\n", encoding: "utf8" });
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /usr\/bin\/redis-server/);
    const good = spawnSync(process.execPath, [tool], { input: "app/server/dist/src/main.js\n", encoding: "utf8" });
    assert.equal(good.status, 0, good.stderr);
    assert.match(good.stdout, /ok: 1 paths/);
  });
});
