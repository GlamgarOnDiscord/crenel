import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { gitHistory } from "./git-history.js";
import { Scope } from "../core/scope.js";

const git = (dir: string, ...args: string[]) => spawnSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });

test("a key removed from the code but still in a past commit is proven; a key still in the tree is left to exposed-secrets", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-git-"));
  try {
    git(dir, "init", "-q");
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src", "pay.ts"), 'const k = "sk_live_51RemovedButStillInHistory0000";\n');
    writeFileSync(join(dir, "src", "gh.ts"), 'const t = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";\n');
    git(dir, "add", "-A"); git(dir, "commit", "-qm", "add keys");
    writeFileSync(join(dir, "src", "pay.ts"), "const k = process.env.STRIPE_KEY;\n");
    git(dir, "commit", "-qam", "remove key");
    const found = await gitHistory.run({ scope: new Scope({ allowedHosts: [] }), projectDir: join(dir, "src"), options: {}, log: () => {} });
    assert.equal(found.length, 1);
    assert.match(found[0]!.id, /^git-history:stripe-secret:/);
    assert.match(found[0]!.location, /^src\/pay\.ts @ [0-9a-f]{7}$/);
    assert.doesNotMatch(JSON.stringify(found), /RemovedButStillInHistory0000/, "the key itself is never in the report");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
