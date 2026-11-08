import { test } from "node:test";
import assert from "node:assert/strict";
import { toSarif } from "./sarif.js";
import type { RunResult } from "../core/runner.js";
import type { Finding } from "../core/types.js";

function f(over: Partial<Finding>): Finding {
  return {
    id: "x", check: "exposed-secrets", title: "t", severity: "critical", state: "proven",
    location: "dist/app.js:5", description: "d", remediation: "r", ...over,
  };
}
function result(findings: Finding[]): RunResult {
  return { project: "p", startedAt: "2026-01-01T00:00:00Z", findings, errors: [], checksRun: [] };
}

test("SARIF has version, a tool driver, and one result per finding", () => {
  const s = JSON.parse(toSarif(result([f({}), f({ id: "y", check: "authz-matrix", severity: "high" })])));
  assert.equal(s.version, "2.1.0");
  assert.equal(s.runs[0].tool.driver.name, "Crenel");
  assert.equal(s.runs[0].results.length, 2);
});

test("severity and state map to SARIF level", () => {
  const s = JSON.parse(toSarif(result([
    f({ id: "a", severity: "critical", state: "proven" }),
    f({ id: "b", severity: "medium", state: "proven" }),
    f({ id: "c", severity: "high", state: "unproven" }),
  ])));
  const by = Object.fromEntries(s.runs[0].results.map((r: any) => [r.properties.id, r.level]));
  assert.equal(by.a, "error");
  assert.equal(by.b, "warning");
  assert.equal(by.c, "note"); // a lead is never a blocking alert
});

test("location path:line becomes uri + startLine", () => {
  const s = JSON.parse(toSarif(result([f({ location: "dist/app.js:5" })])));
  const loc = s.runs[0].results[0].locations[0].physicalLocation;
  assert.equal(loc.artifactLocation.uri, "dist/app.js");
  assert.equal(loc.region.startLine, 5);
});

// GitHub's SARIF requirements:
// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
import { mkdtempSync, mkdirSync, writeFileSync as writeFile } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { randomBytes } from "node:crypto";
import { SARIF_LIMITS, locate } from "./sarif.js";

test("every rule has the properties GitHub lists as required, results reference them", () => {
  const s = JSON.parse(toSarif(result([f({ id: "a" }), f({ id: "b", state: "unproven", severity: "high" })]), { titles: { "exposed-secrets": "Secrets in the bundle" } }));
  const rules = s.runs[0].tool.driver.rules;
  for (const r of rules) {
    assert.ok(r.id && r.shortDescription.text && r.fullDescription.text && r.help.text, `rule ${r.id} incomplete`);
    assert.ok(r.shortDescription.text.length <= 1024 && r.fullDescription.text.length <= 1024);
    assert.ok(r.properties.tags.length <= SARIF_LIMITS.tags);
  }
  for (const res of s.runs[0].results) {
    assert.equal(rules[res.ruleIndex].id, res.ruleId);
    assert.ok(res.message.text);
    assert.equal(res.locations.length, 1);
    assert.ok(res.locations[0].physicalLocation.region.startLine >= 1);
    assert.match(res.partialFingerprints.primaryLocationLineHash, /^[0-9a-f]{16}:1$/);
  }
});

test("a proven rule carries security-severity, a lead has its own rule without it", () => {
  const s = JSON.parse(toSarif(result([f({ id: "a", severity: "critical" }), f({ id: "b", state: "unproven", severity: "critical" })])));
  const byId = Object.fromEntries(s.runs[0].tool.driver.rules.map((r: any) => [r.id, r]));
  assert.equal(byId["exposed-secrets"].properties["security-severity"], "9.5");
  assert.equal(byId["exposed-secrets/lead"].properties["security-severity"], undefined);
  assert.equal(byId["exposed-secrets/lead"].defaultConfiguration.level, "note");
});

test("fixed findings are not emitted (their absence closes the alert)", () => {
  const s = JSON.parse(toSarif(result([f({ id: "a", state: "fixed" })])));
  assert.equal(s.runs[0].results.length, 0);
});

test("fingerprints are stable across runs and distinct per finding", () => {
  const one = JSON.parse(toSarif(result([f({ id: "a" }), f({ id: "b" })]))).runs[0].results;
  const two = JSON.parse(toSarif(result([f({ id: "b" }), f({ id: "a" })]))).runs[0].results;
  const fp = (rs: any[]) => Object.fromEntries(rs.map((r) => [r.properties.id, r.partialFingerprints.primaryLocationLineHash]));
  assert.deepEqual(fp(one), fp(two));
  assert.notEqual(fp(one).a, fp(one).b);
});

test("URLs, hosts and option paths are anchored to the config file: one uri scheme only", () => {
  const root = mkdtempSync(join(tmpdir(), "crenel-sarif-"));
  mkdirSync(join(root, "app", "dist"), { recursive: true });
  writeFile(join(root, "app", "dist", "main.js"), "x\n");
  const opts = { repoRoot: root, projectDir: join(root, "app", "dist"), configPath: join(root, "crenel.config.yaml") };
  const s = JSON.parse(toSarif(result([
    f({ id: "1", location: "main.js:3" }),
    f({ id: "2", location: "https://staging.example.com:8443/api/x" }),
    f({ id: "3", location: "staging.example.com" }),
    f({ id: "4", location: "options.authz-matrix.accounts" }),
    f({ id: "5", location: "https://x.example.com (CORS)" }),
    f({ id: "6", location: "/etc/passwd" }),
  ]), opts));
  const uris = Object.fromEntries(s.runs[0].results.map((r: any) => [r.properties.id, r.locations[0].physicalLocation]));
  assert.deepEqual(uris["1"], { artifactLocation: { uri: "app/dist/main.js" }, region: { startLine: 3 } });
  for (const id of ["2", "3", "4", "5", "6"]) assert.equal(uris[id].artifactLocation.uri, "crenel.config.yaml", id);
  for (const r of s.runs[0].results) assert.doesNotMatch(r.locations[0].physicalLocation.artifactLocation.uri, /^[a-z]+:|^\//i);
  const anchored = s.runs[0].results.find((r: any) => r.properties.id === "2");
  assert.match(anchored.message.text, /staging\.example\.com:8443/);
});

test("locate: a directory is anchored, a path outside the repository too", () => {
  const root = mkdtempSync(join(tmpdir(), "crenel-sarif-"));
  assert.equal(locate(root + "/sub/..", { repoRoot: join(root, "..") }).anchored, true);
  assert.deepEqual(locate(join(root, "pkg.js"), { repoRoot: root }), { uri: "pkg.js", startLine: 1, anchored: false });
  assert.equal(locate("../outside.js", { repoRoot: root }).anchored, true);
});

test("the 10 MB gzipped limit drops leads first", () => {
  // Random messages do not compress: 4,000 leads of ~4 KB weigh well over 10 MB gzipped.
  const noise = (_i: number) => randomBytes(4500).toString("base64");
  const many = Array.from({ length: 4000 }, (_, i) => f({ id: `lead-${i}`, state: "unproven", title: noise(i), remediation: "" }));
  const out = toSarif(result([f({ id: "keep" }), ...many]));
  assert.ok(gzipSync(out).length <= SARIF_LIMITS.gzipBytes);
  const s = JSON.parse(gunzipSync(gzipSync(out)).toString());
  assert.deepEqual(s.runs[0].results.map((r: any) => r.properties.id), ["keep"]);
  assert.match(JSON.stringify(s.runs[0].invocations), /10 MB/);
});
