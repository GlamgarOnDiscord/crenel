import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mcpSurface } from "./mcp-surface.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-mcp-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t", version: "1.0.0" }));
  for (const [name, body] of Object.entries(files)) {
    const full = join(dir, name);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, body);
  }
  return dir;
}

test("no agent config yields no findings", async () => {
  const dir = project({});
  try {
    assert.equal((await mcpSurface.run(ctx(dir))).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a committed .mcp.json is reported, and a command server raises severity to medium", async () => {
  const dir = project({
    ".mcp.json": JSON.stringify({
      mcpServers: {
        local: { command: "node", args: ["server.js"], env: { TOKEN: "x" } },
        remote: { url: "https://example.com/mcp" },
      },
    }),
  });
  try {
    const found = await mcpSurface.run(ctx(dir));
    const f = found.find((x) => x.id === "mcp-surface:config:.mcp.json");
    assert.ok(f, "expected a config finding");
    assert.equal(f!.severity, "medium"); // because 'local' runs a command
    assert.equal(f!.state, "unproven"); // a surface to review, never proven
    assert.match(f!.description, /local/);
    assert.match(f!.description, /remote/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a config with only URL servers stays low severity", async () => {
  const dir = project({
    ".cursor/mcp.json": JSON.stringify({ mcpServers: { r: { url: "https://x/mcp" } } }),
  });
  try {
    const found = await mcpSurface.run(ctx(dir));
    const f = found.find((x) => x.id === "mcp-surface:config:.cursor/mcp.json");
    assert.ok(f);
    assert.equal(f!.severity, "low");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a present but unparseable config is still flagged", async () => {
  const dir = project({ "claude_desktop_config.json": "{ not json" });
  try {
    const found = await mcpSurface.run(ctx(dir));
    assert.ok(found.some((x) => x.id === "mcp-surface:present:claude_desktop_config.json"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a settings file with no server and nothing that runs (attribution only) is not a surface; one with hooks is", async () => {
  const quiet = project({ ".claude/settings.json": JSON.stringify({ $schema: "https://json.schemastore.org/claude-code-settings.json", attribution: { commit: "", pr: "" }, includeCoAuthoredBy: false }) });
  const hooks = project({ ".claude/settings.json": JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "./guard.sh" }] }] } }) });
  try {
    assert.equal((await mcpSurface.run(ctx(quiet))).length, 0);
    const f = await mcpSurface.run(ctx(hooks));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "medium");
    assert.match(f[0]!.description, /sets hooks/);
  } finally {
    rmSync(quiet, { recursive: true, force: true });
    rmSync(hooks, { recursive: true, force: true });
  }
});
