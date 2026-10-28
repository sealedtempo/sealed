// tools/twenty-enterprise-audit.py on a small Twenty-shaped tree: marked files anywhere in the
// file, AGPL importers through every alias, the stub surface and the reach through marked files.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const tool = join(dirname(fileURLToPath(import.meta.url)), "../tools/twenty-enterprise-audit.py");
const python = ["python3", "python"].find((p) => spawnSync(p, ["--version"]).status === 0);

test("counts marked files, AGPL importers and the stub surface", { skip: !python && "python3 not installed" }, async () => {
  const repo = await mkdtemp(join(tmpdir(), "twenty-audit-"));
  try {
    const files = {
      "LICENSE": "/* @license Enterprise */ is the marker\n",
      "packages/twenty-server/src/engine/core-modules/billing/billing.service.ts": "/* @license Enterprise */\nimport { Helper } from 'src/engine/core-modules/billing/helper';\nexport class BillingService {}\n",
      "packages/twenty-server/src/engine/core-modules/billing/helper.ts": "import { X } from 'src/engine/core-modules/x';\n/* @license Enterprise */\nexport class Helper {}\n",
      "packages/twenty-server/src/engine/core-modules/x.ts": "export class X {}\n",
      "packages/twenty-server/src/engine/twenty-orm/repository/workspace-repository.ts": "import {\n  BillingService,\n} from 'src/engine/core-modules/billing/billing.service';\n",
      "packages/twenty-server/src/engine/twenty-orm/repository/workspace-repository.spec.ts": "import { BillingService } from 'src/engine/core-modules/billing/billing.service';\n",
      "packages/twenty-shared/src/types/Rls.ts": "/* @license Enterprise */\nexport type Rls = {};\n",
      "packages/twenty-shared/src/types/index.ts": "export * from './Rls';\n",
      "packages/twenty-front/src/modules/users/fragment.ts": "import { Rls } from 'twenty-shared/types';\nimport { Sso } from '@/settings/sso';\n",
      "packages/twenty-front/src/modules/settings/sso.ts": "/* @license Enterprise */\nexport const Sso = 1;\n",
    };
    for (const [path, body] of Object.entries(files)) {
      await mkdir(dirname(join(repo, path)), { recursive: true });
      await writeFile(join(repo, path), body);
    }
    const out = join(repo, "report.json");
    const res = spawnSync(python, ["-I", tool, repo, "--json", out], { encoding: "utf8" });
    assert.equal(res.status, 0, res.stderr);
    const report = JSON.parse(await readFile(out, "utf8"));
    assert.equal(report.marked_files_total, 4, "LICENSE is not counted; a marker after the imports is");
    assert.equal(report.agpl_production_importers, 3, "workspace-repository, the shared index and the front fragment");
    assert.equal(report.agpl_test_importers, 1);
    assert.equal(report.stub_surface_files, 3);
    assert.equal(report.marked_files_reached_from_production, 4, "helper.ts is reached through billing.service.ts");
    assert.deepEqual(Object.keys(report.core_importers).sort(), [
      "packages/twenty-front/src/modules/users/fragment.ts",
      "packages/twenty-server/src/engine/twenty-orm/repository/workspace-repository.ts",
      "packages/twenty-shared/src/types/index.ts",
    ]);
    assert.match(res.stdout, /marked files: 4/);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});
