import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { openAiCompatibleLlm, ollamaLlm, anthropicApiLlm, resolveLlm, selectLlm } from "./llm.js";

// A throwaway http server: `handler` sees the parsed JSON body and the headers, and
// returns [status, bodyString]. Resolves to the base URL and a close().
function server(handler: (body: any, req: { headers: Record<string, any>; url?: string }) => [number, string]): Promise<{ base: string; seen: any[]; close: () => void }> {
  const seen: any[] = [];
  const srv: Server = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => { raw += d; });
    req.on("end", () => {
      let body: any = null;
      try { body = raw ? JSON.parse(raw) : null; } catch { body = raw; }
      seen.push({ body, headers: req.headers, url: req.url });
      const [status, out] = handler(body, { headers: req.headers, url: req.url });
      res.writeHead(status, { "content-type": "application/json" });
      res.end(out);
    });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, seen, close: () => srv.close() })));
}

test("openai-compatible: reads choices[0].message.content, posts the right body, key only from env", async () => {
  const s = await server(() => [200, JSON.stringify({ choices: [{ message: { content: "  hello from openai  " } }] })]);
  try {
    process.env.CRENEL_TEST_KEY = "sk-test-123";
    const llm = openAiCompatibleLlm("llama3", { baseUrl: s.base, apiKeyEnv: "CRENEL_TEST_KEY" });
    assert.equal(await llm.ask("ping"), "hello from openai");
    const call = s.seen[0];
    assert.equal(call.body.model, "llama3");
    assert.equal(call.body.stream, false);
    assert.deepEqual(call.body.messages, [{ role: "user", content: "ping" }]);
    assert.equal(call.headers.authorization, "Bearer sk-test-123");
  } finally { delete process.env.CRENEL_TEST_KEY; s.close(); }
});

test("openai-compatible: no apiKeyEnv -> no authorization header sent", async () => {
  const s = await server(() => [200, JSON.stringify({ choices: [{ message: { content: "x" } }] })]);
  try {
    const llm = openAiCompatibleLlm("m", { baseUrl: s.base });
    await llm.ask("hi");
    assert.equal(s.seen[0].headers.authorization, undefined);
  } finally { s.close(); }
});

test("openai-compatible: missing content field -> clear error", async () => {
  const s = await server(() => [200, JSON.stringify({ choices: [] })]);
  try {
    const llm = openAiCompatibleLlm("m", { baseUrl: s.base });
    await assert.rejects(llm.ask("hi"), /no choices\[0\]\.message\.content/);
  } finally { s.close(); }
});

test("openai-compatible: non-2xx -> error carries the status", async () => {
  const s = await server(() => [503, "overloaded"]);
  try {
    const llm = openAiCompatibleLlm("m", { baseUrl: s.base });
    await assert.rejects(llm.ask("hi"), /openai-compatible HTTP 503/);
  } finally { s.close(); }
});

test("openai-compatible: invalid JSON body -> error", async () => {
  const s = await server(() => [200, "not json {"]);
  try {
    const llm = openAiCompatibleLlm("m", { baseUrl: s.base });
    await assert.rejects(llm.ask("hi"), /returned invalid JSON/);
  } finally { s.close(); }
});

test("ollama: reads .response from /api/generate", async () => {
  const s = await server((_b, req) => [200, JSON.stringify({ response: req.url === "/api/generate" ? " native ollama " : "wrong path" })]);
  try {
    const llm = ollamaLlm("qwen", { baseUrl: s.base });
    assert.equal(await llm.ask("ping"), "native ollama");
    assert.equal(s.seen[0].url, "/api/generate");
    assert.equal(s.seen[0].body.model, "qwen");
    assert.equal(s.seen[0].body.stream, false);
  } finally { s.close(); }
});

test("anthropic-api: reads content[0].text, sends x-api-key + anthropic-version", async () => {
  const s = await server(() => [200, JSON.stringify({ content: [{ type: "text", text: "claude says hi" }] })]);
  try {
    process.env.CRENEL_TEST_ANTHROPIC = "sk-ant-xyz";
    const llm = anthropicApiLlm("claude-x", { baseUrl: s.base, apiKeyEnv: "CRENEL_TEST_ANTHROPIC" });
    assert.equal(await llm.ask("ping"), "claude says hi");
    assert.equal(s.seen[0].headers["x-api-key"], "sk-ant-xyz");
    assert.equal(s.seen[0].headers["anthropic-version"], "2023-06-01");
    assert.equal(s.seen[0].body.model, "claude-x");
    assert.ok(typeof s.seen[0].body.max_tokens === "number");
  } finally { delete process.env.CRENEL_TEST_ANTHROPIC; s.close(); }
});

test("anthropic-api: missing env var -> throws before any request", async () => {
  delete process.env.CRENEL_TEST_MISSING;
  const llm = anthropicApiLlm("claude-x", { apiKeyEnv: "CRENEL_TEST_MISSING", baseUrl: "http://127.0.0.1:1" });
  await assert.rejects(llm.ask("hi"), /CRENEL_TEST_MISSING is not set/);
});

test("timeoutMs is respected: a slow server makes ask reject", async () => {
  const srv = createServer((_req, res) => { setTimeout(() => { res.writeHead(200); res.end("{}"); }, 2000); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const llm = openAiCompatibleLlm("m", { baseUrl: base });
    await assert.rejects(llm.ask("hi", { timeoutMs: 100 }), /request failed/);
  } finally { srv.close(); }
});

test("call.signal: an already-aborted signal rejects without a request", async () => {
  const llm = openAiCompatibleLlm("m", { baseUrl: "http://127.0.0.1:1" });
  await assert.rejects(llm.ask("hi", { signal: AbortSignal.abort() }), /request failed/);
});

test("resolveLlm: claude CLI models unchanged, providers routed, bad specs -> null", () => {
  assert.equal(resolveLlm("opus")?.label, "claude -p (opus)");
  assert.equal(resolveLlm("sonnet")?.label, "claude -p (sonnet)");
  assert.equal(resolveLlm("gpt-4"), null); // no colon, not a claude model
  assert.ok(resolveLlm("openai:llama3")?.label.startsWith("openai (llama3"));
  assert.ok(resolveLlm("ollama:qwen")?.label.startsWith("ollama (qwen"));
  assert.equal(resolveLlm("anthropic-api:claude-x")?.label, "anthropic-api (claude-x)");
  assert.equal(resolveLlm("openai:"), null); // empty model
  assert.equal(resolveLlm("bogus:m"), null); // unknown provider
});

test("selectLlm: flag spec wins, config fallback works, usesCli flag is correct", () => {
  assert.deepEqual({ cli: selectLlm({}).usesCli, label: selectLlm({}).llm?.label }, { cli: true, label: "claude -p (sonnet)" });
  assert.equal(selectLlm({ spec: "opus" }).usesCli, true);
  assert.equal(selectLlm({ spec: "openai:m", baseUrl: "http://127.0.0.1:9" }).usesCli, false);
  const fromCfg = selectLlm({ config: { provider: "ollama", model: "qwen", baseUrl: "http://127.0.0.1:11434" } });
  assert.equal(fromCfg.usesCli, false);
  assert.ok(fromCfg.llm?.label.startsWith("ollama (qwen"));
});

test("selectLlm: malformed options.llm -> clear error, no llm", () => {
  const r = selectLlm({ config: { provider: "openai", model: "m", apiKeyEnv: "lower-case-bad" } });
  assert.equal(r.llm, null);
  assert.match(r.error ?? "", /options\.llm:/);
  const r2 = selectLlm({ config: { provider: "openai" } }); // provider without model
  assert.match(r2.error ?? "", /requires a model/);
});
