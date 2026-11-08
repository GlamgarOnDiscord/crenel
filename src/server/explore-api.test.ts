import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startServer } from "./http.js";
import { scriptedLlm } from "../agent/llm.js";

async function boot(llm: boolean, configExplore?: string) {
  const dir = mkdtempSync(join(tmpdir(), "crenel-xapi-"));
  const cfg = join(dir, "crenel.config.yaml");
  writeFileSync(cfg, `project: t\nprojectDir: .\n${configExplore ? `explore: ${configExplore}\n` : ""}scope:\n  allowedHosts: [127.0.0.1]\nchecks: []\n`);
  const srv = await startServer({ configPath: cfg, port: 0, token: "tk", webDir: null, llm: llm ? "auto" : "off", claudeAvailable: llm, llmFactory: () => scriptedLlm([]), checks: [] });
  const H = { authorization: "Bearer tk", "content-type": "application/json" };
  return {
    srv, state: async () => (await (await fetch(`${srv.url}/api/state`, { headers: H })).json()) as { explore: string },
    run: async (body: unknown) => (await (await fetch(`${srv.url}/api/runs`, { method: "POST", headers: H, body: JSON.stringify(body) })).json()) as { id: string },
    close: async () => { await srv.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

const wait = async (fn: () => boolean) => { for (let i = 0; i < 300 && !fn(); i++) await new Promise((r) => setTimeout(r, 10)); };

test("api: the state reports the exploration default; a run takes the console's choice", async () => {
  const off = await boot(false);
  try { assert.equal((await off.state()).explore, "off", "no model: off"); } finally { await off.close(); }
  const cfgOff = await boot(true, "off");
  try { assert.equal((await cfgOff.state()).explore, "off", "the config's choice"); } finally { await cfgOff.close(); }
  const c = await boot(true);
  try {
    assert.equal((await c.state()).explore, "assist");
    for (const [choice, expect] of [["full", "full"], ["off", "off"], ["bogus", "assist"]] as const) {
      const { id } = await c.run({ prompt: "/explore", mode: "readonly", explore: choice });
      const r = c.srv.runs.get(id)!;
      await wait(() => r.status === "done" || r.status === "error");
      assert.equal(r.explore, expect, choice);
      assert.equal(r.journal.since(0).some((e) => e.type === "explore.start"), expect !== "off");
    }
  } finally { await c.close(); }
});
