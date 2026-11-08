import { test } from "node:test";
import assert from "node:assert/strict";
import {
  activeModelView, customSpec, draftToModel, emptyDraft, modelSend, parseCustomModels, validateDraft,
  CONNECTORS, connectorOf, connectorToDraft,
  type CustomModel, type ModelDraft,
} from "./workspace.tsx";

const draft = (p: Partial<ModelDraft> = {}): ModelDraft => ({ ...emptyDraft(), ...p });

test("validateDraft: name required, env var is a NAME in upper case, temperature bounded", () => {
  assert.deepEqual(validateDraft(draft({ name: "gpt-4o-mini" })), {}, "a bare valid draft passes");
  assert.ok(validateDraft(draft({ name: "" })).name, "empty name is refused");
  assert.ok(validateDraft(draft({ name: "m", apiKeyEnv: "lower_case" })).apiKeyEnv, "a lower-case env name is refused");
  assert.deepEqual(validateDraft(draft({ name: "m", apiKeyEnv: "CRENEL_LLM_API_KEY" })), {}, "an upper-case env name passes");
  assert.ok(validateDraft(draft({ name: "m", temperature: "3" })).temperature, "temperature > 2 is refused");
  assert.deepEqual(validateDraft(draft({ name: "m", temperature: "0.2" })), {}, "a temperature in range passes");
});

test("draftToModel: trims, carries only a key NAME, drops empty optionals", () => {
  const m = draftToModel(draft({ provider: "openai-compatible", name: "  gpt-4o-mini ", baseUrl: " https://api.openai.com ", apiKeyEnv: "OPENAI_KEY", temperature: "0.5" }), "cm-fixed");
  assert.deepEqual(m, { id: "cm-fixed", provider: "openai-compatible", name: "gpt-4o-mini", baseUrl: "https://api.openai.com", apiKeyEnv: "OPENAI_KEY", temperature: 0.5 });
  const bare = draftToModel(draft({ provider: "ollama", name: "llama3.1" }), "cm-2");
  assert.equal(bare.baseUrl, undefined);
  assert.equal(bare.apiKeyEnv, undefined);
  assert.equal(bare.temperature, undefined);
  // The object only ever holds the NAME of the env var, never a key value.
  assert.ok(!Object.keys(m).some((k) => /key$/i.test(k) && k !== "apiKeyEnv"));
});

test("customSpec: one spec per provider", () => {
  const m = (provider: CustomModel["provider"]): CustomModel => ({ id: "x", provider, name: "mod" });
  assert.equal(customSpec(m("openai-compatible")), "openai:mod");
  assert.equal(customSpec(m("ollama")), "ollama:mod");
  assert.equal(customSpec(m("anthropic-api")), "anthropic-api:mod");
});

test("modelSend: a built-in id passes through; a custom id becomes spec + connection, never a key", () => {
  const custom: CustomModel[] = [{ id: "cm-1", provider: "openai-compatible", name: "gpt-4o-mini", baseUrl: "https://api.openai.com", apiKeyEnv: "OPENAI_KEY" }];
  assert.deepEqual(modelSend("opus", custom), { model: "opus" }, "built-in id is sent unchanged");
  assert.deepEqual(modelSend("cm-1", custom), { model: "openai:gpt-4o-mini", modelBaseUrl: "https://api.openai.com", modelApiKeyEnv: "OPENAI_KEY" });
  // What travels is only the variable name; the serialised body carries no key value.
  const sent = JSON.stringify(modelSend("cm-1", custom));
  assert.ok(sent.includes("OPENAI_KEY") && !/sk-/.test(sent));
  // An unknown id falls back to a plain built-in send.
  assert.deepEqual(modelSend("cm-missing", custom), { model: "cm-missing" });
});

test("activeModelView: built-in, custom, and unknown fallback", () => {
  const custom: CustomModel[] = [{ id: "cm-1", provider: "ollama", name: "llama3.1" }];
  assert.deepEqual(activeModelView("sonnet", custom), { label: "Sonnet 5.5", provider: "claude", custom: false });
  assert.deepEqual(activeModelView("cm-1", custom), { label: "llama3.1", provider: "custom", custom: true });
  const fb = activeModelView("cm-gone", custom);
  assert.equal(fb.custom, false, "an unknown id falls back to a built-in default");
});

test("parseCustomModels: round-trips valid data, drops garbage, never throws", () => {
  const list: CustomModel[] = [
    { id: "cm-1", provider: "openai-compatible", name: "gpt-4o-mini", apiKeyEnv: "OPENAI_KEY" },
    { id: "cm-2", provider: "ollama", name: "llama3.1", temperature: 0.3 },
  ];
  assert.deepEqual(parseCustomModels(JSON.stringify(list)), list, "a saved list is read back as-is");
  assert.deepEqual(parseCustomModels(null), []);
  assert.deepEqual(parseCustomModels("not json"), []);
  assert.deepEqual(parseCustomModels(JSON.stringify({ not: "an array" })), []);
  assert.deepEqual(parseCustomModels(JSON.stringify([{ id: "x", provider: "bogus", name: "m" }])), [], "an unknown provider is filtered out");
});

test("connectors: presets prefill a valid draft and map to the right engine spec", () => {
  assert.ok(CONNECTORS.length >= 12, "a rich set of connectors is offered");
  const groq = connectorOf("groq")!;
  const d = connectorToDraft(groq, "llama-3.1-70b");
  assert.equal(d.provider, "openai-compatible");
  assert.equal(d.baseUrl, "https://api.groq.com/openai/v1");
  assert.equal(d.apiKeyEnv, "GROQ_API_KEY");
  assert.deepEqual(validateDraft(d), {}, "a preset-filled draft is valid");
  assert.equal(customSpec(draftToModel(d)), "openai:llama-3.1-70b");
  // local presets carry no key and are flagged
  assert.equal(connectorOf("ollama")!.local, true);
  assert.equal(connectorToDraft(connectorOf("lmstudio")!).apiKeyEnv, "");
});
