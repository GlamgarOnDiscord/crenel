#!/usr/bin/env node
// Smoke test of a standalone `crenel` executable (scripts/build-sea.mjs), run
// from a temp directory so nothing can come from the repo layout:
//   1. `crenel --version` prints package.json's version;
//   2. `crenel scan` on a copy of examples/ proves the planted Stripe secret and
//      the known-bad package (the latter needs the embedded src/data JSON);
//   3. `crenel serve --port 0` answers on 127.0.0.1 (health, token-to-cookie
//      exchange, the embedded console and one of its assets), then stops.
// Usage: node scripts/smoke-binary.mjs <path to executable>

import { spawn, spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const bin = resolve(process.argv[2] ?? "");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const work = mkdtempSync(join(tmpdir(), "crenel-smoke-"));
cpSync(join(root, "examples", "crenel.config.yaml"), join(work, "crenel.config.yaml"));
cpSync(join(root, "examples", "vulnerable-app"), join(work, "vulnerable-app"), { recursive: true });
const step = (m) => console.log(`smoke: ${m}`);

try {
  // 1. version
  const v = spawnSync(bin, ["--version"], { cwd: work, encoding: "utf8" });
  assert.equal(v.status, 0, v.stderr);
  assert.equal(v.stdout.trim(), `crenel ${pkg.version}`);
  step(`--version ok (${v.stdout.trim()})`);

  // 2. scan: exit 1 because the example ships planted secrets.
  const s = spawnSync(bin, ["scan", "--config", "crenel.config.yaml", "--json"], { cwd: work, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  assert.equal(s.status, 1, `scan exit ${s.status}: ${s.stderr}`);
  const findings = JSON.parse(s.stdout).findings;
  const proven = new Set(findings.filter((f) => f.state === "proven").map((f) => f.id));
  assert.ok(proven.has("exposed-secrets:stripe-secret:app.js:5"), `stripe secret not proven: ${[...proven].join(", ")}`);
  assert.ok([...proven].some((id) => id.startsWith("dependency-risk:known-bad:")), "known-bad package not proven (embedded data missing?)");
  step(`scan ok (${proven.size} proven findings)`);

  // 3. serve on a free port, read the printed link.
  const srv = spawn(bin, ["serve", "--config", "crenel.config.yaml", "--port", "0"], { cwd: work, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  srv.stderr.on("data", (d) => { err += d; });
  const link = await new Promise((ok, ko) => {
    const t = setTimeout(() => ko(new Error(`serve did not print its link in 30 s: ${out}${err}`)), 30_000);
    srv.stdout.on("data", (d) => {
      out += d;
      const m = out.match(/http:\/\/127\.0\.0\.1:\d+\/\?token=[\w-]+/);
      if (m) { clearTimeout(t); ok(m[0]); }
    });
    srv.once("exit", (c) => { clearTimeout(t); ko(new Error(`serve exited ${c}: ${err}`)); });
  });
  const base = new URL(link).origin;
  try {
    const h = await fetch(`${base}/api/health`);
    assert.equal(h.status, 200);
    const x = await fetch(link, { redirect: "manual" });
    assert.equal(x.status, 302);
    const cookie = (x.headers.get("set-cookie") ?? "").split(";")[0];
    assert.match(cookie, /^crenel_token=/);
    const page = await fetch(`${base}/`, { headers: { cookie } });
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /<div id="root"/);
    const asset = html.match(/\/assets\/[\w.-]+\.js/)?.[0];
    assert.ok(asset, "no script in index.html");
    const a = await fetch(`${base}${asset}`);
    assert.equal(a.status, 200);
    assert.match(a.headers.get("content-type") ?? "", /javascript/);
    const api = await fetch(`${base}/api/config`, { headers: { cookie } });
    assert.equal(api.status, 200);
    step(`serve ok (${base}, console ${html.length} B, ${asset})`);
  } finally {
    srv.kill();
    await new Promise((ok) => (srv.exitCode !== null ? ok() : srv.once("exit", ok)));
  }
  step("serve stopped");
} finally {
  rmSync(work, { recursive: true, force: true });
}
console.log("smoke: all good");
