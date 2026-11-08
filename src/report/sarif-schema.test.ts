// Our SARIF against the official OASIS SARIF 2.1.0 JSON schema (draft-04,
// vendored from https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json)
// and against what GitHub's "SARIF support for code scanning" page requires
// (https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).
// The input is a real scan of the bundled example, so every check that finds
// something there is covered, URLs and directories included.

import { test } from "node:test";
import assert from "node:assert/strict";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "../core/config.js";
import { run } from "../core/runner.js";
import { REGISTRY } from "../core/registry.js";
import { toSarif } from "./sarif.js";
import { githubProblems, schemaValidator as validator } from "./sarif-validate.js";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");

test("a real scan's SARIF validates against the OASIS SARIF 2.1.0 schema and GitHub's code scanning requirements", async () => {
  const configPath = join(repo, "examples", "crenel.config.yaml");
  const config = loadConfig(configPath);
  const result = await run(config, configPath, {});
  assert.ok(result.findings.length > 10, "the example must produce findings");
  const sarif: any = JSON.parse(toSarif(result, {
    repoRoot: repo, projectDir: resolve(dirname(configPath), config.projectDir), configPath,
    titles: Object.fromEntries(REGISTRY.map((c) => [c.name, c.title])),
  }));
  const validate = validator();
  const doc: unknown = sarif;
  assert.ok(validate(doc), JSON.stringify(validate.errors?.slice(0, 5), null, 2));
  assert.deepEqual(githubProblems(sarif), []);
  assert.ok(sarif.runs[0].results.some((r: any) => r.locations[0].physicalLocation.artifactLocation.uri === "examples/crenel.config.yaml"), "some findings are anchored");
});

test("the validators catch what GitHub would reject", () => {
  const bad = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
    runs: [{ tool: { driver: { name: "x", rules: [{ id: "r" }] } }, results: [
      { ruleId: "r", message: { text: "m" }, locations: [{ physicalLocation: { artifactLocation: { uri: "https://a.example/x" } } }] },
      { ruleId: "r", message: { text: "m" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/a.js" }, region: { startLine: 0 } } }] },
    ] }],
  };
  const problems = githubProblems(bad);
  assert.ok(problems.some((p) => /shortDescription/.test(p)));
  assert.ok(problems.some((p) => /mixed uri schemes/.test(p)));
  assert.ok(problems.some((p) => /startLine/.test(p)));
  assert.equal(validator()(bad), false, "startLine 0 breaks the schema's minimum");
});
