import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dockerfile } from "./dockerfile.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-docker-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t" }));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

test("no Dockerfile yields no findings", async () => {
  const dir = project({});
  try { assert.equal((await dockerfile.run(ctx(dir))).length, 0); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a risky Dockerfile is flagged across the rules", async () => {
  const dir = project({
    Dockerfile: [
      "FROM node:latest",
      "ARG NPM_TOKEN=npm_abcdefghijklmnop",
      "ADD https://example.com/x.sh /x.sh",
      "RUN curl https://get.example.com | sh",
      'CMD ["node", "server.js"]',
    ].join("\n"),
  });
  try {
    const ids = (await dockerfile.run(ctx(dir))).map((f) => f.id.split(":")[1]);
    assert.ok(ids.includes("root"), "no USER -> root");
    assert.ok(ids.includes("base"), "node:latest -> unpinned base");
    assert.ok(ids.includes("secret"), "inline NPM_TOKEN -> baked secret");
    assert.ok(ids.includes("add-url"), "ADD url");
    assert.ok(ids.includes("pipe-sh"), "curl | sh");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a hardened Dockerfile yields no findings", async () => {
  const dir = project({
    Dockerfile: [
      "FROM node:22.10.0-bookworm-slim@sha256:" + "a".repeat(64),
      "COPY . /app",
      "USER node",
      'CMD ["node", "server.js"]',
    ].join("\n"),
  });
  try {
    assert.equal((await dockerfile.run(ctx(dir))).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("findings are leads, never proven", async () => {
  const dir = project({ "Dockerfile.prod": "FROM alpine\nRUN echo hi\n" });
  try {
    const found = await dockerfile.run(ctx(dir));
    assert.ok(found.length > 0);
    assert.ok(found.every((f) => f.state === "unproven"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
