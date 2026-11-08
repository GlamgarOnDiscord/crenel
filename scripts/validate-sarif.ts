// Validate a SARIF file against the OASIS SARIF 2.1.0 schema and GitHub's
// code scanning requirements (see src/report/sarif-validate.ts).
//   npx tsx scripts/validate-sarif.ts crenel.sarif
import { readFileSync } from "node:fs";
import { validateSarif } from "../src/report/sarif-validate.js";

const file = process.argv[2];
if (!file) { process.stderr.write("usage: tsx scripts/validate-sarif.ts <file.sarif>\n"); process.exit(2); }
const r = validateSarif(JSON.parse(readFileSync(file, "utf8")));
for (const e of r.schema) process.stderr.write(`schema: ${e}\n`);
for (const e of r.github) process.stderr.write(`github: ${e}\n`);
const n = JSON.parse(readFileSync(file, "utf8")).runs?.[0]?.results?.length ?? 0;
process.stdout.write(r.schema.length || r.github.length ? `${file}: invalid\n` : `${file}: valid SARIF 2.1.0 for GitHub code scanning (${n} results)\n`);
process.exit(r.schema.length || r.github.length ? 1 : 0);
