import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runConfined } from "./docker.js";

// A fake `docker` that journals its argv and hangs on `run`, like a long tool.
function fakeDocker(): { bin: string; log: string; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "crenel-fake-docker-"));
  const log = join(dir, "calls.log"), bin = join(dir, "docker");
  writeFileSync(bin, `#!/bin/sh\necho "$*" >> ${JSON.stringify(log)}\nif [ "$1" = run ]; then exec sleep 30; fi\nexit 0\n`);
  chmodSync(bin, 0o755);
  return { bin, log, dir };
}

test("an aborted run without network removes its container (killing the docker client does not stop it)", { skip: process.platform === "win32" }, async () => {
  const f = fakeDocker();
  const prev = process.env.CRENEL_DOCKER;
  process.env.CRENEL_DOCKER = f.bin;
  try {
    const ac = new AbortController();
    const p = runConfined({ argv: ["trufflehog", "filesystem", "/project"], scope: null, tool: "trufflehog", signal: ac.signal });
    setTimeout(() => ac.abort(), 300);
    await p;
    const calls = readFileSync(f.log, "utf8").split("\n").filter(Boolean);
    const name = calls[0]!.match(/--name (crenel-tool-[0-9a-f]+)/)?.[1];
    assert.ok(name, calls[0]);
    assert.ok(calls.some((c) => c === `rm -f ${name}`), `no rm -f after abort: ${calls.join(" | ")}`);
  } finally {
    if (prev === undefined) delete process.env.CRENEL_DOCKER; else process.env.CRENEL_DOCKER = prev;
    rmSync(f.dir, { recursive: true, force: true });
  }
});
