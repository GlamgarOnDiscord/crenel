#!/usr/bin/env node
// Refresh src/data/retire-js.json from the retire.js signature repository
// (https://github.com/RetireJS/retire.js, Apache-2.0). Public data, read-only,
// no credentials. Run locally: `node scripts/sync-retire-db.mjs [path-or-url]`.
//
// The upstream file is ~640 KB; what the static check cannot use is dropped, so
// the embedded copy stays small (~100 KB):
//   - `func` extractors (JavaScript evaluated inside a live page) and `ast`
//     queries (need a JS parser and retire's query engine): not runnable by a
//     static, no-execution scanner;
//   - advisories with neither a CVE nor a GHSA id (end-of-life notices, bug
//     tracker entries): not a documented advisory, so they can prove nothing;
//   - info links, CWE lists, licenses.
// Patterns are copied verbatim: nothing is added, so no target's answer can
// slip in here.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "..", "src", "data", "retire-js.json");
const SOURCE = process.argv[2] ?? "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json";

const raw = /^https?:/.test(SOURCE) ? await (await fetch(SOURCE)).text() : readFileSync(SOURCE, "utf8");
const upstream = JSON.parse(raw);

const libs = {};
let advisories = 0;
for (const [name, entry] of Object.entries(upstream).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
  const ex = entry.extractors ?? {};
  const vulns = [];
  for (const v of entry.vulnerabilities ?? []) {
    const cve = v.identifiers?.CVE ?? [];
    const ghsa = v.identifiers?.githubID;
    if (cve.length === 0 && !ghsa) continue;
    if (!v.below && !v.atOrAbove) continue;
    const out = {};
    if (v.atOrAbove) out.atOrAbove = v.atOrAbove;
    if (v.below) out.below = v.below;
    out.severity = v.severity ?? "medium";
    if (cve.length) out.cve = cve;
    if (ghsa) out.ghsa = ghsa;
    if (v.identifiers?.summary) out.summary = String(v.identifiers.summary).slice(0, 160);
    vulns.push(out);
  }
  if (vulns.length === 0) continue;
  const lib = {};
  for (const k of ["filecontent", "filecontentreplace", "filename", "uri"]) if (ex[k]?.length) lib[k] = ex[k];
  if (ex.hashes && Object.keys(ex.hashes).length) lib.hashes = ex.hashes;
  if (Object.keys(lib).length === 0) continue; // no extractor a static scan can run
  lib.vulnerabilities = vulns;
  libs[name] = lib;
  advisories += vulns.length;
}

const doc = {
  source: "https://github.com/RetireJS/retire.js (repository/jsrepository-v4.json), Apache-2.0",
  syncedAt: new Date().toISOString().slice(0, 10),
  libs,
};
writeFileSync(OUT, JSON.stringify(doc, null, 1) + "\n");
console.log(`retire-js.json: ${Object.keys(libs).length} libraries, ${advisories} advisories, ${JSON.stringify(doc).length} bytes (minified)`);
