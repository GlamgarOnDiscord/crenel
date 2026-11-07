import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigSchema } from "../core/config.js";
import { AgentRun, intentOf } from "../agent/run.js";
import { StateStore } from "../agent/state.js";
import { gateDeterministic } from "../agent/gate.js";
import { Scope } from "../core/scope.js";
import { exposedSecrets } from "../checks/exposed-secrets.js";

test("without Docker, a full scan with the toolbox enabled still runs every other check, with a clear note", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-tb-agent-"));
  const prev = process.env.CRENEL_DOCKER;
  process.env.CRENEL_DOCKER = join(dir, "no-docker-here");
  try {
    writeFileSync(join(dir, "app.js"), `const k = "ghp_${"Q7rS9tU1vW3xY5zA2bC4dE6fG8hJ0kL2mN4p"}";\n`);
    const config = ConfigSchema.parse({ project: "t", projectDir: dir, scope: { allowedHosts: [] }, options: { toolbox: { enabled: true } } });
    const store = new StateStore(join(dir, ".crenel"));
    for (const prompt of ["/scan", "/tools"]) {
      const run = new AgentRun({ config, configPath: join(dir, "crenel.config.yaml"), store, grants: new Set(), llm: null, checks: [exposedSecrets] }, { prompt, mode: "bypass" });
      await run.start();
      assert.equal(run.status, "done", prompt);
      const notes = run.journal.since(0).filter((e) => e.type === "ui").map((e) => JSON.stringify(e.data));
      assert.ok(notes.some((n) => n.includes("tools.trufflehog") && n.includes("Docker is not installed")), `${prompt}: a clear note says why the toolbox is off`);
    }
    const items = store.findings().items;
    assert.ok(items.some((f) => f.check === "exposed-secrets" && f.state === "proven"), "the rest of Crenel works as before");
  } finally {
    if (prev === undefined) delete process.env.CRENEL_DOCKER; else process.env.CRENEL_DOCKER = prev;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("toolbox tools in the gate: nuclei is active testing, trufflehog offline, undeclared hosts denied", () => {
  const scope = new Scope({ allowedHosts: ["staging.example.test"] });
  const ctx = { scope, mode: "bypass" as const, grants: new Set<string>(), userRequest: "" };
  assert.equal(gateDeterministic({ tool: "tools.trufflehog" }, ctx).verdict, "allow");
  assert.equal(gateDeterministic({ tool: "tools.katana", requests: [{ method: "GET", url: "https://staging.example.test/" }] }, ctx).verdict, "allow");
  const n = gateDeterministic({ tool: "tools.nuclei", requests: [{ method: "GET", url: "https://staging.example.test/" }] }, ctx);
  assert.equal(n.verdict, "deny");
  assert.match(n.reasons.join(" "), /allowActiveTesting/);
  assert.equal(gateDeterministic({ tool: "tools.katana", requests: [{ method: "GET", url: "https://other.example.test/" }] }, ctx).verdict, "deny");
  assert.equal(intentOf("/tools"), "tools");
});
