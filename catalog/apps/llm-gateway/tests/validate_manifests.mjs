// Validate catalog manifests against catalog/schema/manifest.schema.json with Ajv (draft 2020-12).
// The validator packages live outside the workspace, in a throwaway directory:
//   mkdir -p tmp/validator && cd tmp/validator && echo '{"private":true}' > package.json \
//     && pnpm add -E --ignore-workspace ajv@8.17.1 ajv-formats@3.0.1 yaml@2.8.1
//   SEALED_VALIDATOR_DIR=tmp/validator node catalog/apps/llm-gateway/tests/validate_manifests.mjs <manifest.yaml>...
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../../..");
const validatorDir = resolve(process.env.SEALED_VALIDATOR_DIR ?? join(repo, "tmp/validator"));
const require = createRequire(join(validatorDir, "package.json"));
const Ajv2020 = require("ajv/dist/2020").default;
const addFormats = require("ajv-formats").default;
const YAML = require("yaml");

const schema = JSON.parse(readFileSync(join(repo, "catalog/schema/manifest.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error("usage: validate_manifests.mjs <manifest.yaml>...");
  process.exit(2);
}
let failed = 0;
for (const file of files) {
  const doc = YAML.parse(readFileSync(file, "utf8"));
  if (validate(doc)) {
    console.log(`ok   ${file}`);
  } else {
    failed += 1;
    for (const err of validate.errors) console.log(`FAIL ${file}: ${err.instancePath || "/"} ${err.message}`);
  }
}
process.exit(failed ? 1 : 0);
