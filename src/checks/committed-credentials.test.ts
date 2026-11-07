import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { committedCredentials } from "./committed-credentials.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(d: string): CheckContext { return { scope: new Scope({ allowedHosts: [] }), projectDir: d, options: {}, log: () => {} }; }
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-cred-"));
  for (const [n, b] of Object.entries(files)) writeFileSync(join(dir, n), b);
  return dir;
}

test("a committed .npmrc with an auth token is a proven critical", async () => {
  const dir = project({ ".npmrc": "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnop\n" });
  try {
    const found = await committedCredentials.run(ctx(dir));
    assert.equal(found.length, 1);
    assert.equal(found[0]!.severity, "critical");
    assert.equal(found[0]!.state, "proven");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test(".git-credentials and .netrc with passwords are flagged", async () => {
  const dir = project({
    ".git-credentials": "https://user:pass@github.com\n",
    ".netrc": "machine api.example.com login u password s3cret\n",
  });
  try {
    assert.equal((await committedCredentials.run(ctx(dir))).length, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("an .npmrc without a credential (just a registry URL) is not flagged", async () => {
  const dir = project({ ".npmrc": "registry=https://registry.npmjs.org/\n" });
  try {
    assert.equal((await committedCredentials.run(ctx(dir))).length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a plain top-level config.json with an auth field is NOT flagged (ubiquitous name)", async () => {
  // config.json is everywhere; only a Docker registry auth under .docker/ is one.
  const dir = project({ "config.json": '{"auth":"dXNlcjpwYXNz"}\n' });
  try {
    assert.equal((await committedCredentials.run(ctx(dir))).length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a .docker/config.json with an auth field IS flagged", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-cred-"));
  mkdirSync(join(dir, ".docker"));
  writeFileSync(join(dir, ".docker", "config.json"), '{"auths":{"registry":{"auth":"dXNlcjpwYXNz"}}}\n');
  try {
    const found = await committedCredentials.run(ctx(dir));
    assert.equal(found.length, 1);
    assert.equal(found[0]!.location, ".docker/config.json"); // finding paths are always POSIX
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
