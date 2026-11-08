// Validation of a SARIF file, for tests and for CI (scripts/validate-sarif.ts):
//   - the official OASIS SARIF 2.1.0 JSON schema (draft-04), vendored in
//     schemas/ from https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json;
//   - what GitHub's "SARIF support for code scanning" page requires and limits
//     (https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).
// Dev-only: ajv is a devDependency, the CLI never imports this file.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import Ajv from "ajv-draft-04";
import addFormats from "ajv-formats";
import { SARIF_LIMITS } from "./sarif.js";

const here = dirname(fileURLToPath(import.meta.url));

/** Every rule GitHub lists as required for code scanning, and its limits. */
export function githubProblems(sarif: any): string[] {
  const out: string[] = [];
  if (sarif.version !== "2.1.0" || !sarif.$schema || !Array.isArray(sarif.runs)) out.push("top level: $schema, version 2.1.0 and runs are required");
  if (sarif.runs.length > 20) out.push("more than 20 runs");
  for (const r of sarif.runs) {
    const rules = r.tool?.driver?.rules ?? [];
    if (!r.tool?.driver?.name) out.push("tool.driver.name is required");
    if (!Array.isArray(r.results)) out.push("results is required");
    if (r.results.length > SARIF_LIMITS.results) out.push("more than 25,000 results");
    if (rules.length > SARIF_LIMITS.rules) out.push("more than 25,000 rules");
    for (const rule of rules) {
      if (!rule.id || !rule.shortDescription?.text || !rule.fullDescription?.text || !rule.help?.text) out.push(`rule ${rule.id}: id, shortDescription, fullDescription and help are required`);
      if (rule.shortDescription?.text.length > 1024 || rule.fullDescription?.text.length > 1024) out.push(`rule ${rule.id}: description over 1,024 characters`);
      if ((rule.name ?? "").length > 255) out.push(`rule ${rule.id}: name over 255 characters`);
      if ((rule.properties?.tags ?? []).length > SARIF_LIMITS.tags) out.push(`rule ${rule.id}: more than 20 tags`);
      const sev = rule.properties?.["security-severity"];
      if (sev !== undefined && !(Number(sev) > 0 && Number(sev) <= 10)) out.push(`rule ${rule.id}: security-severity out of (0, 10]`);
      if (rule.defaultConfiguration && !["note", "warning", "error"].includes(rule.defaultConfiguration.level)) out.push(`rule ${rule.id}: bad level`);
    }
    const schemes = new Set<string>();
    for (const res of r.results) {
      if (!res.message?.text) out.push("result without message.text");
      if (!Array.isArray(res.locations) || res.locations.length < 1) out.push(`${res.ruleId}: at least one location is required`);
      if (res.locations?.length > 1000) out.push(`${res.ruleId}: more than 1,000 locations`);
      if (res.ruleIndex !== undefined && rules[res.ruleIndex]?.id !== res.ruleId) out.push(`${res.ruleId}: ruleIndex points elsewhere`);
      for (const loc of res.locations ?? []) {
        const uri: string = loc.physicalLocation?.artifactLocation?.uri ?? "";
        if (!uri) out.push(`${res.ruleId}: artifactLocation.uri is required`);
        schemes.add(/^[a-z][a-z0-9+.-]*:/i.test(uri) ? uri.split(":")[0]! : "(relative)");
        if (/^\/|^[a-z]:\\|\.\.\//i.test(uri)) out.push(`${res.ruleId}: ${uri} is not relative to the repository`);
        if (!(loc.physicalLocation?.region?.startLine >= 1)) out.push(`${res.ruleId}: region.startLine is required`);
      }
      if (!res.partialFingerprints?.primaryLocationLineHash) out.push(`${res.ruleId}: no primaryLocationLineHash`);
    }
    if (schemes.size > 1) out.push(`mixed uri schemes: ${[...schemes].join(", ")}`);
  }
  if (gzipSync(JSON.stringify(sarif)).length > SARIF_LIMITS.gzipBytes) out.push("over 10 MB gzipped");
  return out;
}

export function schemaValidator() {
  const schema = JSON.parse(readFileSync(join(here, "schemas", "sarif-schema-2.1.0.json"), "utf8"));
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv.compile(schema);
}


/** Schema errors (first 20) and GitHub problems; both empty means valid. */
export function validateSarif(doc: unknown): { schema: string[]; github: string[] } {
  const v = schemaValidator();
  const ok = v(doc);
  const schema = ok ? [] : (v.errors ?? []).slice(0, 20).map((e) => `${e.instancePath || "/"} ${e.message ?? ""}`);
  return { schema, github: githubProblems(doc) };
}
