import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ssrf } from "./ssrf.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-ssrf-"));
  for (const [n, b] of Object.entries(files)) writeFileSync(join(dir, n), b);
  return dir;
}

test("a URL from searchParams flowing into fetch is a high lead", async () => {
  const dir = project({ "preview.ts": 'export async function GET(req: Request) {\n  const target = new URL(req.url).searchParams.get("url")!;\n  const page = await fetch(target);\n  return new Response(await page.text());\n}\n' });
  try {
    const found = await ssrf.run(ctx(dir));
    assert.equal(found.length, 1);
    assert.equal(found[0]!.location, "preview.ts:3");
    assert.equal(found[0]!.state, "unproven");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("direct and destructured request input are caught too", async () => {
  const dir = project({
    "a.js": "app.get('/p', async (req, res) => { const r = await axios.get(req.query.url); res.send(r.data); });\n",
    "b.js": "app.post('/p', async (req, res) => { const { link } = req.body; res.send(await got(link).text()); });\n",
  });
  try { assert.deepEqual((await ssrf.run(ctx(dir))).map((f) => f.location).sort(), ["a.js:1", "b.js:1"]); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});

test("an allowlisted host check, or a fetch of a constant, is not flagged", async () => {
  const dir = project({
    "avatar.ts": 'const ALLOWED = new Set(["avatars.githubusercontent.com"]);\nexport async function GET(req: Request) {\n  const target = new URL(new URL(req.url).searchParams.get("src")!);\n  if (!ALLOWED.has(target.hostname)) return new Response("no", { status: 400 });\n  return fetch(target);\n}\n',
    "const.ts": 'export async function GET(req: Request) {\n  const id = new URL(req.url).searchParams.get("id");\n  return fetch("https://api.example.com/items");\n}\n',
  });
  try { assert.equal((await ssrf.run(ctx(dir))).length, 0); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});
