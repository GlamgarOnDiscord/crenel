import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { startServer } from "./http.js";
import { readJournal } from "../agent/journal.js";

// A mock OpenAI-compatible endpoint: records the model asked for and the
// Authorization header it received, then answers with one chat completion.
function mockOpenAi() {
  const seen: { model?: string; auth?: string }[] = [];
  const srv = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      let model: string | undefined;
      try { model = JSON.parse(body).model; } catch { /* ignore */ }
      seen.push({ model, auth: req.headers.authorization });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ choices: [{ message: { content: "Compris, je reste dans le périmètre." } }] }));
    });
  });
  return new Promise<{ url: string; seen: typeof seen; close: () => Promise<void> }>((ok) => {
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as { port: number }).port;
      ok({ url: `http://127.0.0.1:${port}`, seen, close: () => new Promise<void>((r) => srv.close(() => r())) });
    });
  });
}

async function boot(llm: "auto" | "off" = "auto") {
  const dir = mkdtempSync(join(tmpdir(), "crenel-cm-"));
  const cfg = join(dir, "crenel.config.yaml");
  writeFileSync(cfg, `project: t\nprojectDir: .\nscope:\n  allowedHosts: [127.0.0.1]\nchecks: []\n`);
  // claudeAvailable:false on purpose — an HTTP custom model never needs the CLI.
  const srv = await startServer({ configPath: cfg, port: 0, token: "tk", webDir: null, llm, claudeAvailable: false, checks: [] });
  const H = { authorization: "Bearer tk", "content-type": "application/json" };
  return {
    srv, dir,
    post: (path: string, body: unknown) => fetch(`${srv.url}${path}`, { method: "POST", headers: H, body: JSON.stringify(body) }),
    get: (path: string) => fetch(`${srv.url}${path}`, { headers: H }),
    close: async () => { await srv.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

const wait = async (fn: () => boolean) => { for (let i = 0; i < 400 && !fn(); i++) await new Promise((r) => setTimeout(r, 10)); };

test("a custom OpenAI-compatible model is resolved and honoured; only the env-var NAME travels", async () => {
  const mock = await mockOpenAi();
  const c = await boot();
  const SECRET = "sk-fake-supersecret-value-9999";
  process.env.CRENEL_TEST_KEY = SECRET;
  try {
    const res = await c.post("/api/runs", { prompt: "bonjour, résume l'état", mode: "readonly", model: "openai:test-model", modelBaseUrl: mock.url, modelApiKeyEnv: "CRENEL_TEST_KEY" });
    assert.equal(res.status, 201, await res.clone().text());
    const { id } = await res.json() as { id: string };
    const run = c.srv.runs.get(id)!;
    await wait(() => run.status === "done" || run.status === "error" || run.status === "stopped");
    assert.equal(run.status, "done", "the run completed with the custom model");

    // The engine called the endpoint with the right model and read the key from env.
    assert.ok(mock.seen.some((s) => s.model === "test-model"), "the provider was asked for the custom model");
    assert.ok(mock.seen.some((s) => s.auth === `Bearer ${SECRET}`), "the key was read from the environment at call time");

    // run.start records the resolved provider label and spec, with no key anywhere.
    const journalText = readFileSync(join(c.dir, ".crenel", "runs", `${id}.jsonl`), "utf8");
    const start = readJournal(join(c.dir, ".crenel", "runs", `${id}.jsonl`)).find((e) => e.type === "run.start")!;
    const data = start.data as { llm: string | null; model: string | null };
    assert.equal(data.model, "openai:test-model");
    assert.match(data.llm ?? "", /^openai \(test-model @ http:\/\/127\.0\.0\.1:\d+\)$/);
    assert.ok(!journalText.includes(SECRET), "the key value never reaches the journal");
    let audit = ""; try { audit = readFileSync(join(c.dir, ".crenel", "audit.jsonl"), "utf8"); } catch { /* none written */ }
    assert.ok(!audit.includes(SECRET), "the key value never reaches the audit log");

    // /api/state lists the supported provider names, never a secret.
    const state = await (await c.get("/api/state")).json() as { customProviders: string[] };
    assert.deepEqual(state.customProviders, ["openai", "ollama", "anthropic-api"]);
  } finally {
    delete process.env.CRENEL_TEST_KEY;
    await c.close();
    await mock.close();
  }
});

test("a bad custom model is a clear 4xx, with no secret disclosed", async () => {
  const c = await boot();
  try {
    assert.equal((await c.post("/api/runs", { prompt: "x", model: "bogus:thing" })).status, 400, "unknown provider");
    assert.equal((await c.post("/api/runs", { prompt: "x", model: "openai:m", modelApiKeyEnv: "lower_case" })).status, 400, "env var name must be upper-case");
    assert.equal((await c.post("/api/runs", { prompt: "x", model: "openai:m", modelBaseUrl: "not a url" })).status, 400, "base URL must be valid");
    // A plain built-in name is unchanged: no model available here, the run still starts.
    assert.equal((await c.post("/api/runs", { prompt: "x", model: "opus" })).status, 201);
  } finally { await c.close(); }
});

test("when the server is started with --llm off, a custom model is refused", async () => {
  const c = await boot("off");
  try {
    const res = await c.post("/api/runs", { prompt: "x", model: "openai:m", modelBaseUrl: "http://127.0.0.1:1" });
    assert.equal(res.status, 400);
    const state = await (await c.get("/api/state")).json() as { customProviders: string[] };
    assert.deepEqual(state.customProviders, [], "no providers advertised when model access is off");
  } finally { await c.close(); }
});
