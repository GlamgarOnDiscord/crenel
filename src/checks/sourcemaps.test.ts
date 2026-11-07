import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sourcemaps } from "./sourcemaps.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-map-"));
  for (const [name, body] of Object.entries(files)) {
    const full = join(dir, name);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, body);
  }
  return dir;
}

test("a .map file in the bundle is flagged", async () => {
  const dir = project({ "app.js": "console.log(1)", "app.js.map": '{"version":3}' });
  try {
    const found = await sourcemaps.run(ctx(dir));
    assert.ok(found.some((f) => f.id === "sourcemaps:file:app.js.map"));
    assert.ok(found.every((f) => f.state === "unproven"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a sourceMappingURL comment pointing at an external map is flagged", async () => {
  const dir = project({ "app.js": "console.log(1)\n//# sourceMappingURL=app.js.map\n" });
  try {
    const ids = (await sourcemaps.run(ctx(dir))).map((f) => f.id);
    assert.ok(ids.some((i) => i.startsWith("sourcemaps:ref:")));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("an inline data: source map is not flagged", async () => {
  const dir = project({ "app.js": "x\n//# sourceMappingURL=data:application/json;base64,eyJ9\n" });
  try {
    assert.equal((await sourcemaps.run(ctx(dir))).length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a clean bundle yields nothing", async () => {
  const dir = project({ "app.js": "console.log(1)", "index.html": "<html></html>" });
  try {
    assert.equal((await sourcemaps.run(ctx(dir))).length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
