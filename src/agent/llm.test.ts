import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { openAiCompatibleLlm, ollamaLlm, anthropicApiLlm, resolveLlm, selectLlm, endpointUrl, displayBase, checkModelEndpoint, claudeCli, presentModelKeys, parseEffort, anthropicSupportsEffort } from "./llm.js";

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
    assert.equal(s.seen[0].headers["anthropic-version"], "2026-10-21");
    assert.equal(s.seen[0].body.model, "claude-x");
    assert.ok(typeof s.seen[0].body.max_tokens === "number");
  } finally { delete process.env.CRENEL_TEST_ANTHROPIC; s.close(); }
});

// M4: a provider redirect is never followed, so the key never reaches the redirect's host.
test("anthropic-api: a redirect is refused and the key goes nowhere else", async () => {
  const other = await server(() => [200, JSON.stringify({ content: [{ type: "text", text: "stolen" }] })]);
  const redirector = createServer((_q, r) => { r.writeHead(307, { location: other.base + "/v1/messages" }); r.end(); });
  await new Promise<void>((r) => redirector.listen(0, "127.0.0.1", r));
  try {
    process.env.CRENEL_TEST_ANTHROPIC = "sk-ant-xyz";
    const llm = anthropicApiLlm("claude-x", { baseUrl: `http://127.0.0.1:${(redirector.address() as AddressInfo).port}`, apiKeyEnv: "CRENEL_TEST_ANTHROPIC" });
    await assert.rejects(llm.ask("ping"), /request failed/);
    assert.equal(other.seen.length, 0);
  } finally { delete process.env.CRENEL_TEST_ANTHROPIC; other.close(); redirector.close(); }
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
  // A live server that would answer: only the signal can make this reject, and it must not be reached.
  const s = await server(() => [200, JSON.stringify({ choices: [{ message: { content: "ok" } }] })]);
  try {
    const llm = openAiCompatibleLlm("m", { baseUrl: s.base });
    await assert.rejects(llm.ask("hi", { signal: AbortSignal.abort() }), /request failed/);
    assert.equal(s.seen.length, 0);
  } finally { s.close(); }
});

test("timeoutMs covers the body: headers then a stalled body still rejects", async () => {
  const srv = createServer((_req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.write("{"); /* never ends */ });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const llm = openAiCompatibleLlm("m", { baseUrl: base });
    await assert.rejects(llm.ask("hi", { timeoutMs: 200 }), /request failed/);
  } finally { srv.closeAllConnections(); srv.close(); }
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
  // Both given: the flag's spec wins over options.llm.
  const both = selectLlm({ spec: "opus", config: { provider: "ollama", model: "qwen", baseUrl: "http://127.0.0.1:11434" } });
  assert.equal(both.llm?.label, "claude -p (opus)");
});

test("selectLlm: malformed options.llm -> clear error, no llm", () => {
  const r = selectLlm({ config: { provider: "openai", model: "m", apiKeyEnv: "lower-case-bad" } });
  assert.equal(r.llm, null);
  assert.match(r.error ?? "", /options\.llm:/);
  const r2 = selectLlm({ config: { provider: "openai" } }); // provider without model
  assert.match(r2.error ?? "", /requires a model/);
});

test("endpointUrl: a bare host gets /v1, a base that already has a path only gets the resource", () => {
  const chat = (b: string) => endpointUrl(b, "/v1", "/chat/completions");
  assert.equal(chat("https://api.deepseek.com"), "https://api.deepseek.com/v1/chat/completions");
  assert.equal(chat("https://api.openai.com/v1"), "https://api.openai.com/v1/chat/completions");
  assert.equal(chat("https://api.openai.com/v1/"), "https://api.openai.com/v1/chat/completions");
  assert.equal(chat("https://openrouter.ai/api/v1"), "https://openrouter.ai/api/v1/chat/completions");
  assert.equal(chat("https://api.groq.com/openai/v1"), "https://api.groq.com/openai/v1/chat/completions");
  assert.equal(chat("https://generativelanguage.googleapis.com/v1beta/openai"), "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions");
  assert.equal(chat("http://127.0.0.1:11434"), "http://127.0.0.1:11434/v1/chat/completions");
  assert.equal(endpointUrl("https://api.anthropic.com", "/v1", "/messages"), "https://api.anthropic.com/v1/messages");
  assert.equal(endpointUrl("https://api.anthropic.com/v1", "/v1", "/messages"), "https://api.anthropic.com/v1/messages");
});

test("displayBase: credentials in a base URL never reach a label", () => {
  assert.equal(displayBase("https://user:pass@models.example.com/v1/"), "https://models.example.com/v1");
  const llm = openAiCompatibleLlm("m", { baseUrl: "https://user:pass@models.example.com/v1" });
  assert.ok(!llm.label.includes("pass"), llm.label);
});

test("checkModelEndpoint: only model-key env vars, https or loopback, no URL credentials, no remote scan target", () => {
  assert.equal(checkModelEndpoint({ apiKeyEnv: "OPENAI_API_KEY", baseUrl: "https://api.openai.com/v1" }), null);
  assert.equal(checkModelEndpoint({ apiKeyEnv: "CRENEL_LLM_KEY" }), null);
  assert.equal(checkModelEndpoint({ apiKeyEnv: "MY_GATEWAY_KEY", configKeyEnv: "MY_GATEWAY_KEY" }), null);
  assert.match(checkModelEndpoint({ apiKeyEnv: "GITHUB_TOKEN" }) ?? "", /not a model key/);
  assert.match(checkModelEndpoint({ apiKeyEnv: "AWS_SECRET_ACCESS_KEY" }) ?? "", /not a model key/);
  assert.match(checkModelEndpoint({ apiKeyEnv: "sk-live-123" }) ?? "", /NAME/);
  assert.equal(checkModelEndpoint({ baseUrl: "http://127.0.0.1:1234/v1" }), null);
  assert.equal(checkModelEndpoint({ baseUrl: "http://localhost:11434" }), null);
  assert.match(checkModelEndpoint({ baseUrl: "http://models.example.com" }) ?? "", /https/);
  assert.match(checkModelEndpoint({ baseUrl: "https://a:b@models.example.com" }) ?? "", /credentials/);
  assert.match(checkModelEndpoint({ baseUrl: "https://app.example.com/v1", scanHosts: ["app.example.com"] }) ?? "", /scan target/);
  assert.equal(checkModelEndpoint({ baseUrl: "http://127.0.0.1:11434", scanHosts: ["127.0.0.1"] }), null, "a local model next to a local target");
});

test("claudeCli: inherited object keys are not models", () => {
  assert.equal(claudeCli("constructor"), null);
  assert.equal(claudeCli("__proto__"), null);
  assert.equal(claudeCli("toString"), null);
  assert.ok(claudeCli("opus-4-8"));
});

test("selectLlm: a request temperature wins over the config's", async () => {
  let got: number | undefined;
  const srv = createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { got = JSON.parse(b).temperature; res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ choices: [{ message: { content: "ok" } }] })); }); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
  try {
    const port = (srv.address() as AddressInfo).port;
    const { llm } = selectLlm({ spec: "openai:m", baseUrl: `http://127.0.0.1:${port}`, temperature: 0.7, config: { temperature: 0.1 } });
    await llm!.ask("hi");
    assert.equal(got, 0.7);
  } finally { await new Promise<void>((r) => srv.close(() => r())); }
});

test("presentModelKeys: names of the model keys that are set, never other variables", () => {
  const env = { OPENAI_API_KEY: "x", GROQ_API_KEY: "", CRENEL_LLM_GATEWAY: "y", GITHUB_TOKEN: "z", MY_KEY: "w" };
  assert.deepEqual(presentModelKeys(env), ["CRENEL_LLM_GATEWAY", "OPENAI_API_KEY"]);
  assert.deepEqual(presentModelKeys(env, "MY_KEY"), ["CRENEL_LLM_GATEWAY", "MY_KEY", "OPENAI_API_KEY"]);
});

test("parseEffort: the console's stops and the API's names, nothing else", () => {
  assert.equal(parseEffort("low"), "low");
  assert.equal(parseEffort("med"), "medium");
  assert.equal(parseEffort("max"), "max");
  assert.equal(parseEffort("xhigh"), "xhigh");
  assert.equal(parseEffort("turbo"), undefined);
  assert.equal(parseEffort(3), undefined);
});

test("claudeCli: the effort reaches the CLI (shown in the label); none keeps the CLI default", () => {
  assert.equal(claudeCli("opus-4-8", { effort: "high" })!.label, "claude -p (opus-4-8, effort high)");
  assert.equal(claudeCli("sonnet")!.label, "claude -p (sonnet)");
});

test("anthropic-api: output_config.effort only for models that take it", async () => {
  assert.ok(anthropicSupportsEffort("claude-opus-4-8"));
  assert.ok(anthropicSupportsEffort("claude-opus-5-5"));
  assert.ok(anthropicSupportsEffort("claude-sonnet-4-6"));
  assert.ok(anthropicSupportsEffort("claude-haiku-5-5"));
  assert.ok(!anthropicSupportsEffort("claude-haiku-4-5"), "Haiku 4.5 rejects effort");
  assert.ok(!anthropicSupportsEffort("claude-sonnet-4-5"));
  assert.ok(!anthropicSupportsEffort("claude-opus-4-5"), "Opus 4.5 has no max level");
  const bodies: Record<string, unknown>[] = [];
  const srv = createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { bodies.push(JSON.parse(b)); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ content: [{ type: "text", text: "ok" }] })); }); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
  process.env.CRENEL_LLM_TEST_ANTHROPIC = "k";
  try {
    const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    await anthropicApiLlm("claude-opus-4-8", { baseUrl: base, apiKeyEnv: "CRENEL_LLM_TEST_ANTHROPIC", effort: "max" }).ask("hi");
    await anthropicApiLlm("claude-haiku-4-5", { baseUrl: base, apiKeyEnv: "CRENEL_LLM_TEST_ANTHROPIC", effort: "max" }).ask("hi");
    assert.deepEqual(bodies[0]?.output_config, { effort: "max" });
    assert.equal(bodies[1]?.output_config, undefined);
  } finally { delete process.env.CRENEL_LLM_TEST_ANTHROPIC; await new Promise<void>((r) => srv.close(() => r())); }
});

test("endpointUrl: a full endpoint is taken as given (DeepSeek's documented URL)", () => {
  assert.equal(endpointUrl("https://api.deepseek.com/chat/completions", "/v1", "/chat/completions"), "https://api.deepseek.com/chat/completions");
  assert.equal(endpointUrl("https://api.anthropic.com/v1/messages", "/v1", "/messages"), "https://api.anthropic.com/v1/messages");
});

test("endpointUrl: a query stays a query and a fragment is dropped", () => {
  assert.equal(endpointUrl("https://x.example/openai/v1?api-version=2024-10-21", "/v1", "/chat/completions"), "https://x.example/openai/v1/chat/completions?api-version=2024-10-21");
  assert.equal(endpointUrl("https://x.example#frag", "/v1", "/chat/completions"), "https://x.example/v1/chat/completions");
});

test("presentModelKeys: a CRENEL_LLM_ name that is not a valid env name is never reported", () => {
  assert.deepEqual(presentModelKeys({ "CRENEL_LLM_ok": "x", CRENEL_LLM_KEY: "y" } as NodeJS.ProcessEnv), ["CRENEL_LLM_KEY"]);
});
