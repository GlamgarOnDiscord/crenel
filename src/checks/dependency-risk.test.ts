import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dependencyRisk, parseLockedVersions } from "./dependency-risk.js";
import denylistData from "../data/known-bad-packages.json" with { type: "json" };
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}

// A name@version that is really on the bundled denylist, so the test stays true
// to what ships rather than to a hand-picked string.
const KNOWN_BAD = (() => {
  const p = (denylistData as { packages: { name: string; version: string }[] }).packages[0];
  if (!p) throw new Error("denylist is empty");
  return `${p.name}@${p.version}`;
})();

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-dep-"));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

test("parseLockedVersions reads the pnpm v9 shape", () => {
  const text = [
    "packages:",
    "  '@tanstack/react-router@1.169.5(react@18.3.1)':",
    "    resolution: {integrity: sha512-x}",
    "  lodash@4.17.21:",
    "    resolution: {integrity: sha512-y}",
  ].join("\n");
  const got = parseLockedVersions(text);
  assert.ok(got.has("@tanstack/react-router@1.169.5"));
  assert.ok(got.has("lodash@4.17.21"));
});

test("parseLockedVersions reads the npm v3 shape", () => {
  const text = JSON.stringify({
    packages: {
      "node_modules/left-pad": { version: "1.3.0" },
      "node_modules/@scope/pkg": { version: "2.0.1" },
    },
  });
  const got = parseLockedVersions(text);
  assert.ok(got.has("left-pad@1.3.0"));
  assert.ok(got.has("@scope/pkg@2.0.1"));
});

test("a locked denylisted version is a PROVEN critical", async () => {
  const [name, version] = [KNOWN_BAD.slice(0, KNOWN_BAD.lastIndexOf("@")), KNOWN_BAD.slice(KNOWN_BAD.lastIndexOf("@") + 1)];
  const dir = project({
    "package.json": JSON.stringify({ name: "t", version: "1.0.0" }),
    "pnpm-lock.yaml": `packages:\n  '${name}@${version}':\n    resolution: {integrity: sha512-z}\n`,
  });
  try {
    const found = await dependencyRisk.run(ctx(dir));
    const bad = found.find((f) => f.id.startsWith("dependency-risk:known-bad:"));
    assert.ok(bad, "expected a known-bad finding");
    assert.equal(bad!.severity, "critical");
    assert.equal(bad!.state, "proven");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a clean lockfile yields no known-bad finding", async () => {
  const dir = project({
    "package.json": JSON.stringify({ name: "t", version: "1.0.0" }),
    "pnpm-lock.yaml": "packages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-a}\n",
  });
  try {
    const found = await dependencyRisk.run(ctx(dir));
    assert.ok(!found.some((f) => f.id.startsWith("dependency-risk:known-bad:")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("install hooks and non-registry deps are leads, missing lockfile too", async () => {
  const dir = project({
    "package.json": JSON.stringify({
      name: "t",
      version: "1.0.0",
      scripts: { postinstall: "node build.js" },
      dependencies: { evil: "git+https://example.com/evil.git" },
    }),
  });
  try {
    const found = await dependencyRisk.run(ctx(dir));
    const ids = found.map((f) => f.id);
    assert.ok(ids.some((i) => i === "dependency-risk:install-script:postinstall"));
    assert.ok(ids.some((i) => i === "dependency-risk:non-registry:evil"));
    assert.ok(ids.some((i) => i === "dependency-risk:no-lockfile"));
    // every one of these is a lead, never a gate
    assert.ok(found.filter((f) => ["install-script", "non-registry", "no-lockfile"].some((k) => f.id.includes(k))).every((f) => f.state === "unproven"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
