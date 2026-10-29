// images/espocrm: the entrypoint (sealed-espocrm.sh) run under every POSIX shell on the machine
// with stand-ins for id, stat, chown, setpriv, php and apache2, plus static checks of the
// Dockerfile and the Apache configuration. The image itself is built by the runtime image
// workflow (no Docker daemon here); its build runs the PHP and Apache self-checks.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { closeSync, existsSync, openSync, readFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import { parsePhpConfig } from "./lib/fake-espocrm.mjs";

const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const imageDir = join(appDir, "images/espocrm");
const script = join(imageDir, "sealed-espocrm.sh");
const dockerfile = readFileSync(join(imageDir, "Dockerfile"), "utf8");
const apacheConf = readFileSync(join(imageDir, "apache-sealed.conf"), "utf8");
const manifest = parse(readFileSync(join(appDir, "manifest.yaml"), "utf8"));
const shells = ["/bin/sh", "/bin/dash", "/bin/bash"].filter((s) => existsSync(s));

const PG = "0123abcd".repeat(8);
const URL_OK = "https://crm.34-1-2-3.sslip.io";
const SWITCHES = manifest.telemetry_off_env;

async function sandbox({ uid = "33", installed = "true", owner = "33:33" } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "crm-entrypoint-"));
  const bin = join(dir, "bin");
  const espo = join(dir, "html");
  const skel = join(dir, "skel");
  const log = join(dir, "log");
  await mkdir(bin);
  await mkdir(join(espo, "data"), { recursive: true });
  await mkdir(join(skel, "custom/Espo/Custom"), { recursive: true });
  await mkdir(join(skel, "client/custom/modules"), { recursive: true });
  await mkdir(join(skel, "data"), { recursive: true });
  await writeFile(join(skel, "custom/Espo/Custom/.htaccess"), "Deny from all\n");
  await writeFile(join(skel, "client/custom/modules/dummy.txt"), "");
  await writeFile(join(skel, "data/.data"), "");
  const stub = async (name, body) => {
    await writeFile(join(bin, name), `#!/bin/sh\n${body}\n`);
    await chmod(join(bin, name), 0o755);
  };
  const record = (name) => `printf '%s\\n' "${name} $*" >> '${log}'`;
  await stub("id", `[ "$1" = "-u" ] && echo ${uid} || /usr/bin/id "$@"`);
  await stub("stat", `echo ${owner}`);
  await stub("chown", record("chown"));
  await stub("setpriv", `${record("setpriv")}\nexit 0`);
  await stub("php", `${record("php")}\n[ "$2" = "config:get" ] && { echo ${installed}; exit 0; }\nexit 0`);
  await stub("apache2", record("apache2"));
  await stub("sleep", "exit 0");
  const env = {
    PATH: `${bin}:/usr/bin:/bin`,
    SEALED_ESPO_DIR: espo,
    SEALED_ESPO_SKEL: skel,
    SEALED_PUBLIC_URL_CRM: URL_OK,
    PG_DATABASE_PASSWORD: PG,
    ...SWITCHES,
  };
  return {
    dir,
    espo,
    env,
    run: (shell, args, extra = {}, stdio = "pipe") =>
      spawnSync(shell, [script, ...args], { env: { ...env, ...extra }, encoding: "utf8", cwd: dir, stdio }),
    log: async () => (existsSync(log) ? (await readFile(log, "utf8")).trim().split("\n") : []),
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}

for (const shell of shells) {
  describe(`sealed-espocrm under ${shell}`, () => {
    test("write-config writes both override files with the fixed values", async () => {
      const box = await sandbox();
      try {
        const res = box.run(shell, ["write-config", join(box.espo, "data")]);
        assert.equal(res.status, 0, res.stderr);
        const overrideText = await readFile(join(box.espo, "data/config-override.php"), "utf8");
        const internalText = await readFile(join(box.espo, "data/config-internal-override.php"), "utf8");
        assert.match(overrideText, /^<\?php\n/);
        const override = parsePhpConfig(overrideText);
        assert.deepEqual(override, {
          siteUrl: URL_OK,
          useWebSocket: false,
          adminNotifications: false,
          adminNotificationsNewVersion: false,
          adminNotificationsNewExtensionVersion: false,
          adminNotificationsCronIsNotConfigured: false,
          adminPanelIframeDisabled: true,
          adminPanelIframeUrl: "about:blank",
          adminExtensionUpload: false,
          adminUpgrade: false,
          adminUpgradeDisabled: true,
          phpExecutablePath: "/usr/bin/php",
        });
        assert.deepEqual(parsePhpConfig(internalText).database, {
          platform: "Postgresql", host: "crm-db", port: 5432, dbname: "espocrm", user: "espocrm", password: PG,
        });
        for (const f of ["config-override.php", "config-internal-override.php"]) {
          assert.equal((await stat(join(box.espo, "data", f))).mode & 0o777, 0o600, f);
        }
        assert.ok(!overrideText.includes(PG), "the password is only in the internal file");
      } finally {
        await box.cleanup();
      }
    });

    const bad = [
      ["no public URL", { SEALED_PUBLIC_URL_CRM: "" }, /SEALED_PUBLIC_URL_CRM is not set/],
      ["an http URL", { SEALED_PUBLIC_URL_CRM: "http://crm.example" }, /must start with https/],
      ["a URL with a path", { SEALED_PUBLIC_URL_CRM: "https://crm.example/x" }, /no path or trailing slash/],
      ["a trailing slash", { SEALED_PUBLIC_URL_CRM: "https://crm.example/" }, /no path or trailing slash/],
      ["a quote in the URL", { SEALED_PUBLIC_URL_CRM: "https://crm.example'x" }, /no path or trailing slash/],
      ["no database password", { PG_DATABASE_PASSWORD: "" }, /PG_DATABASE_PASSWORD must be set/],
      ["a quote in the password", { PG_DATABASE_PASSWORD: `${"a".repeat(20)}'` }, /only \[A-Za-z0-9\]/],
      ["a short password", { PG_DATABASE_PASSWORD: "abc123" }, /16 to 128 characters/],
      ["update checks on", { ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS: "true" }, /ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS must be false/],
      ["a missing switch", { ESPOCRM_CONFIG_ADMIN_EXTENSION_UPLOAD: undefined }, /ESPOCRM_CONFIG_ADMIN_EXTENSION_UPLOAD must be false.*got unset/],
      ["an unknown mode", null, /usage: sealed-espocrm/],
    ];
    for (const [name, change, message] of bad) {
      test(`refuses ${name} and writes nothing`, async () => {
        const box = await sandbox();
        try {
          const extra = { ...(change ?? {}) };
          for (const [k, v] of Object.entries(extra)) if (v === undefined) delete box.env[k];
          for (const k of Object.keys(extra)) if (extra[k] === undefined) delete extra[k];
          const res = box.run(shell, change === null ? ["shell"] : ["server"], extra);
          assert.notEqual(res.status, 0);
          assert.match(res.stderr, message);
          assert.ok(!existsSync(join(box.espo, "data/config-override.php")));
          assert.ok(!res.stderr.includes(PG), "the password is never echoed");
        } finally {
          await box.cleanup();
        }
      });
    }

    test("as root: gives the volumes to www-data, then re-runs itself through setpriv", async () => {
      const box = await sandbox({ uid: "0", owner: "0:0" });
      try {
        const res = box.run(shell, ["bootstrap", "node", "x.mjs"], { STATE_DIR: join(box.dir, "state") });
        assert.equal(res.status, 0, res.stderr);
        const log = await box.log();
        for (const d of ["data", "custom", "client/custom"]) {
          assert.ok(log.includes(`chown -R 33:33 ${box.espo}/${d}`), log.join("\n"));
        }
        assert.ok(log.includes(`chown -R 33:33 ${join(box.dir, "state")}`));
        const setpriv = log.find((l) => l.startsWith("setpriv "));
        assert.equal(
          setpriv,
          `setpriv --reuid=33 --regid=33 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs -- ${script} bootstrap node x.mjs`,
        );
        assert.ok(!existsSync(join(box.espo, "data/config-override.php")), "nothing is written as root");
      } finally {
        await box.cleanup();
      }
    });

    test("as root with volumes already owned by www-data: no chown of the volumes", async () => {
      const box = await sandbox({ uid: "0", owner: "33:33" });
      try {
        assert.equal(box.run(shell, ["server"]).status, 0);
        assert.ok(!(await box.log()).some((l) => l.startsWith("chown -R")));
      } finally {
        await box.cleanup();
      }
    });

    // images-preflight: Docker gives a container that starts as root its stdout and stderr as
    // root-owned 0600 pipes, and Apache opens ErrorLog /proc/self/fd/2 by path, so after setpriv it
    // exited with "could not open error log file /proc/self/fd/2" and crm-server never started.
    test("as root: gives its stdout and stderr pipes to www-data before setpriv", async () => {
      const box = await sandbox({ uid: "0", owner: "33:33" });
      try {
        // Node gives a child sockets, not pipes, so a shell pipeline stands in for Docker's pipes.
        const res = spawnSync(shell, ["-c", '"$0" "$1" server 2>&1 | cat; exit "$?"', shell, script], { env: box.env, encoding: "utf8", cwd: box.dir });
        assert.equal(res.status, 0, res.stdout);
        const log = await box.log();
        const setpriv = log.findIndex((l) => l.startsWith("setpriv "));
        assert.ok(setpriv > 0, log.join("\n"));
        for (const fd of [1, 2]) {
          const i = log.indexOf(`chown 33:33 /dev/fd/${fd}`);
          assert.ok(i >= 0 && i < setpriv, log.join("\n"));
        }
      } finally {
        await box.cleanup();
      }
    });

    test("as root: leaves stdout and stderr alone when they are not pipes", async () => {
      const box = await sandbox({ uid: "0", owner: "33:33" });
      const out = openSync(join(box.dir, "out.txt"), "w");
      try {
        assert.equal(box.run(shell, ["server"], {}, ["ignore", out, out]).status, 0);
        const log = await box.log();
        assert.ok(log.some((l) => l.startsWith("setpriv ")), log.join("\n"));
        assert.ok(!log.some((l) => l.includes("/dev/fd/")), log.join("\n"));
      } finally {
        closeSync(out);
        await box.cleanup();
      }
    });

    test("server: seeds the volumes, migrates an installed EspoCRM, then starts Apache", async () => {
      const box = await sandbox();
      try {
        await mkdir(join(box.espo, "custom/Espo/Custom"), { recursive: true });
        await writeFile(join(box.espo, "custom/Espo/Custom/.htaccess"), "kept\n");
        const res = box.run(shell, ["server"]);
        assert.equal(res.status, 0, res.stderr);
        assert.deepEqual(await box.log(), [
          "php bin/command config:get isInstalled",
          "php bin/command clear-cache",
          "php bin/command migrate",
          "apache2 -f /etc/apache2/sealed.conf -DFOREGROUND",
        ]);
        assert.equal(await readFile(join(box.espo, "custom/Espo/Custom/.htaccess"), "utf8"), "kept\n", "never overwrites");
        assert.ok(existsSync(join(box.espo, "client/custom/modules/dummy.txt")));
        assert.ok(existsSync(join(box.espo, "data/.data")));
        assert.ok(existsSync(join(box.espo, "data/config-override.php")));
      } finally {
        await box.cleanup();
      }
    });

    test("server: a fresh volume starts Apache without migrating", async () => {
      const box = await sandbox({ installed: "false" });
      try {
        assert.equal(box.run(shell, ["server"]).status, 0);
        assert.deepEqual(await box.log(), ["php bin/command config:get isInstalled", "apache2 -f /etc/apache2/sealed.conf -DFOREGROUND"]);
      } finally {
        await box.cleanup();
      }
    });

    test("daemon: runs php daemon.php once installed", async () => {
      const box = await sandbox();
      try {
        assert.equal(box.run(shell, ["daemon"]).status, 0);
        assert.deepEqual((await box.log()).slice(-1), ["php daemon.php"]);
      } finally {
        await box.cleanup();
      }
    });

    test("refuses to run as a uid other than root or www-data", async () => {
      const box = await sandbox({ uid: "1000" });
      try {
        const res = box.run(shell, ["server"]);
        assert.notEqual(res.status, 0);
        assert.match(res.stderr, /must run as root or as www-data/);
      } finally {
        await box.cleanup();
      }
    });
  });
}

describe("secrets stay out of argv", () => {
  test("the database password only appears in shell builtins and the heredoc", () => {
    const text = readFileSync(script, "utf8");
    const uses = text.split("\n").filter((l) => /\$pw\b|\$\{#pw\}|PG_DATABASE_PASSWORD/.test(l) && !/^(#|\/\/)/.test(l.trim()));
    for (const line of uses) {
      assert.match(line.trim(), /^(pw=|case \$pw in|\[ "\$\{#pw\}"|'password' => '\$pw',|'' \| \*\[!A-Za-z0-9\]\*\) die "PG_DATABASE_PASSWORD)/, line);
    }
  });
});

describe("Dockerfile", () => {
  test("pins the base image by digest and the Debian packages by snapshot date", () => {
    assert.match(dockerfile, /^ARG DEBIAN_SNAPSHOT=\d{8}T\d{6}Z$/m);
    const froms = dockerfile.split("\n").filter((l) => l.startsWith("FROM "));
    const base = /^FROM (docker\.io\/library\/debian:trixie-\d{8}-slim@sha256:[0-9a-f]{64})/.exec(froms[0])?.[1];
    assert.ok(base, froms[0]);
    assert.deepEqual(froms, [`FROM ${base} AS fetch`, `FROM ${base}`]);
    assert.ok(dockerfile.includes(`org.opencontainers.image.base.digest="${base.split("@")[1]}"`));
    assert.equal(dockerfile.match(/snapshot\.debian\.org\/archive\/debian\/\$\{DEBIAN_SNAPSHOT\} trixie main/g).length, 2);
    assert.match(dockerfile, /rm -f \/etc\/apt\/sources\.list\.d\/debian\.sources/);
  });

  test("checks the EspoCRM release against its sha256 and version", () => {
    assert.match(dockerfile, /ARG ESPOCRM_VERSION=10\.0\.11/);
    assert.match(dockerfile, /ARG ESPOCRM_SHA256=cdd04f7efa52a59025ef824c75b06e0a84cf986724a8c5bc4b56fcd2ce8e0ab1/);
    assert.match(dockerfile, /sha256sum -c -/);
    assert.match(dockerfile, /--proto '=https'/);
    assert.equal(manifest.upstream.version, "10.0.11");
  });

  test("removes the web installer and keeps the writable directories as skeletons", () => {
    assert.match(dockerfile, /rm -rf \/espocrm\/install \/espocrm\/public\/install/);
    assert.match(dockerfile, /test ! -e \/var\/www\/html\/install;/);
    assert.match(dockerfile, /test ! -e \/var\/www\/html\/public\/install;/);
    for (const d of ["data", "custom", "client/custom"]) assert.ok(dockerfile.includes(`mv /espocrm/${d} /skel/${d}`), d);
    assert.match(dockerfile, /COPY --from=fetch \/skel \/opt\/espocrm\/skel/);
  });

  test("fails the build on non-AGPL application code, enterprise markers or Composer licenses off the list", () => {
    assert.match(dockerfile, /test "\$\(ls \/espocrm\/application\/Espo\/Modules\)" = "Crm"/);
    assert.match(dockerfile, /! -exec grep -q 'GNU Affero General Public License'/);
    assert.match(dockerfile, /'@license Enterprise'/);
    assert.match(dockerfile, /Composer packages outside the license allowlist/);
    assert.doesNotMatch(dockerfile, /"(SSPL|BUSL|Elastic|proprietary)/i);
  });

  test("installs only Debian packages at run time and checks the runtime", () => {
    for (const pkg of ["apache2", "libapache2-mod-php8.4", "php8.4-pgsql", "nodejs"]) assert.ok(dockerfile.includes(pkg), pkg);
    assert.doesNotMatch(dockerfile, /pecl|composer install|npm install|pip install/);
    assert.match(dockerfile, /apache2 -f \/etc\/apache2\/sealed\.conf -t/);
    assert.match(dockerfile, /php -l \/tmp\/selftest\/config-override\.php/);
    for (const [name, value] of Object.entries(SWITCHES)) assert.ok(dockerfile.includes(`${name}=${value}`), name);
  });

  test("copies every file it names and nothing else", async () => {
    const copies = [...dockerfile.matchAll(/^COPY (?:--\S+ )*(\S+) \S+$/gm)].map((m) => m[1]).filter((s) => !s.startsWith("/"));
    assert.deepEqual(copies.sort(), ["apache-sealed.conf", "php-sealed.ini", "php-sealed.ini", "sealed-espocrm.sh"]);
    for (const f of copies) assert.ok(existsSync(join(imageDir, f)), f);
  });

  test("ends with the sealed-espocrm entrypoint and port 8080", () => {
    assert.match(dockerfile, /^ENTRYPOINT \["\/usr\/local\/bin\/sealed-espocrm"\]$/m);
    assert.match(dockerfile, /^EXPOSE 8080$/m);
    assert.match(dockerfile, /org\.opencontainers\.image\.licenses="AGPL-3\.0-or-later"/);
  });
});

describe("Apache configuration", () => {
  test("listens on the route port and serves public/ with the /client/ alias", () => {
    assert.match(apacheConf, new RegExp(`^Listen ${manifest.routes[0].internal_port}$`, "m"));
    assert.match(apacheConf, /^DocumentRoot \/var\/www\/html\/public$/m);
    assert.match(apacheConf, /^Alias \/client\/ \/var\/www\/html\/client\/$/m);
    assert.match(apacheConf, /<Directory \/>\n\s+Options None\n\s+AllowOverride None\n\s+Require all denied/);
  });

  test("drops the Authorization header before EspoCRM can read it as a login", () => {
    assert.match(apacheConf, /^RequestHeader unset Authorization early$/m);
    assert.match(apacheConf, /^LoadModule headers_module /m);
  });

  test("never runs PHP from client/ (client/custom is writable)", () => {
    assert.match(apacheConf, /<Directory \/var\/www\/html\/client\/>\n\s+<FilesMatch "\\\.\(php\|phtml\|phar\)\$">\n\s+SetHandler none\n\s+Require all denied/);
  });

  test("trusts forwarded client addresses only from Caddy", () => {
    assert.match(apacheConf, /^RemoteIPHeader X-Forwarded-For$/m);
    assert.match(apacheConf, /^RemoteIPInternalProxy 172\.30\.0\.4$/m);
  });

  test("loads only the modules it configures", () => {
    const mods = [...apacheConf.matchAll(/^LoadModule (\S+) /gm)].map((m) => m[1]);
    assert.deepEqual(mods.sort(), [
      "alias_module", "authz_core_module", "dir_module", "headers_module", "mime_module", "mpm_prefork_module",
      "php_module", "remoteip_module", "reqtimeout_module", "rewrite_module",
    ]);
    assert.doesNotMatch(apacheConf, /status_module|autoindex_module|cgi/);
  });
});
