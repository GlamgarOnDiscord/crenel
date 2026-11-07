import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cloudflareAudit } from "./cloudflare-audit.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string, report?: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: report ? { "cloudflare-audit": { report } } : {}, log: () => {} };
}

const sample = [
  { verdict: "confirmed", fingerprint: "fp1", title: "SQLi dans la recherche", description: "d", remediation: { strategy: "paramétrer la requête", code_changes: [{ file_name: "db.ts", fixed_code: "db.query(sql, [id])" }] }, severity: { overall_severity: "high" }, trace: [{ kind: "entrypoint", file: "a.ts", line: 1 }, { kind: "sink", file: "db.ts", line: 42 }] },
  { verdict: "needs_validation", fingerprint: "fp2", title: "Peut-être un IDOR", trace: [{ kind: "sink", file: "api.ts", line: 7 }] },
  { verdict: "rejected", fingerprint: "fp3", title: "faux positif" },
];

test("imports confirmed as proven and needs_validation as lead, drops rejected", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-cf-"));
  try {
    writeFileSync(join(dir, "findings.json"), JSON.stringify(sample));
    const out = await cloudflareAudit.run(ctx(dir, "findings.json"));
    assert.equal(out.length, 2);
    const confirmed = out.find((f) => f.id.endsWith("fp1"))!;
    assert.equal(confirmed.state, "proven");
    assert.equal(confirmed.severity, "high");
    assert.equal(confirmed.location, "db.ts:42"); // sink preferred
    assert.match(confirmed.remediation, /paramétrer la requête/); // strategy string extracted from the object
    assert.doesNotMatch(confirmed.remediation, /\[object Object\]/);
    const lead = out.find((f) => f.id.endsWith("fp2"))!;
    assert.equal(lead.state, "unproven");
    assert.equal(out.find((f) => f.id.endsWith("fp3")), undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("without a report path, returns a single not-configured lead", async () => {
  const out = await cloudflareAudit.run(ctx("/tmp"));
  assert.equal(out.length, 1);
  assert.equal(out[0]!.state, "unproven");
});
