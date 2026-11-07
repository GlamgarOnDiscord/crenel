#!/usr/bin/env node
// Refresh src/data/known-bad-packages.json from OSV. Reads public advisory data
// (read-only, no credentials) and extracts exact malicious name@version pairs.
// Run in CI on a schedule, or locally: `node scripts/sync-denylist.mjs`.
//
// Pass advisory ids as args, or rely on the default seed list below.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "..", "src", "data", "known-bad-packages.json");

const ADVISORIES = process.argv.slice(2).length
  ? process.argv.slice(2)
  : ["GHSA-g7cv-rxg3-hmpx"]; // @tanstack/* malware

async function fetchAdvisory(id) {
  const res = await fetch(`https://api.osv.dev/v1/vulns/${id}`);
  if (!res.ok) throw new Error(`OSV ${id}: HTTP ${res.status}`);
  return res.json();
}

function* pairsOf(adv) {
  const note = (adv.summary || adv.id || "").slice(0, 120);
  for (const a of adv.affected ?? []) {
    const name = a.package?.name;
    if (!name) continue;
    for (const v of a.versions ?? []) {
      yield { name, version: v, advisory: adv.id, note };
    }
  }
}

const existing = JSON.parse(readFileSync(OUT, "utf8"));
const seen = new Set((existing.packages ?? []).map((p) => `${p.name}@${p.version}`));
const merged = [...(existing.packages ?? [])];
let added = 0;

for (const id of ADVISORIES) {
  try {
    const adv = await fetchAdvisory(id);
    for (const p of pairsOf(adv)) {
      const key = `${p.name}@${p.version}`;
      if (!seen.has(key)) { seen.add(key); merged.push(p); added++; }
    }
    console.log(`${id}: ok`);
  } catch (err) {
    console.error(`${id}: ${err.message}`);
    process.exitCode = 1;
  }
}

merged.sort((a, b) => (a.name + a.version).localeCompare(b.name + b.version));
const out = {
  _comment: existing._comment,
  _sources: [...new Set([...(existing._sources ?? []), ...ADVISORIES.map((id) => `https://github.com/advisories/${id}`)])],
  packages: merged,
};
writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
console.log(`Denylist: ${merged.length} entries (+${added}).`);
