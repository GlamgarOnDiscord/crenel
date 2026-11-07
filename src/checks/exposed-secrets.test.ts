import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exposedSecrets } from "./exposed-secrets.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}

test("detects a Stripe secret key and classifies it critical+proven", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec-"));
  try {
    writeFileSync(join(dir, "app.js"), 'const k = "sk_live_ABCDEFGHIJKLMNOP1234";\n');
    const found = await exposedSecrets.run(ctx(dir));
    const stripe = found.find((f) => f.id.includes("stripe-secret"));
    assert.ok(stripe, "should find the Stripe key");
    assert.equal(stripe!.severity, "critical");
    assert.equal(stripe!.state, "proven");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a clean directory yields no findings, and node_modules is skipped", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec-"));
  try {
    writeFileSync(join(dir, "app.js"), 'const k = "pk_live_safe_publishable";\n');
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules", "x.js"), 'sk_live_SHOULDBESKIPPED123456\n');
    const found = await exposedSecrets.run(ctx(dir));
    assert.equal(found.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a Stripe test key is a low-severity note, not a critical incident", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec-"));
  try {
    writeFileSync(join(dir, "app.js"), 'const k = "sk_test_ABCDEFGHIJKLMNOP1234";\n');
    const found = await exposedSecrets.run(ctx(dir));
    const hit = found.find((f) => f.id.includes("stripe-secret-test"));
    assert.ok(hit, "test key should still be detected");
    assert.equal(hit!.severity, "low");
    assert.doesNotMatch(hit!.description + hit!.remediation, /compromis|compromised|rotate now/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("detects additional distinctive-prefix secrets (slack, npm, github fine-grained, google oauth, sendgrid)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec2-"));
  try {
    writeFileSync(join(dir, "bundle.js"), [
      'a="xoxb-123456789012-abcdefghijkl"',
      'b="npm_' + "lM3nO5pQ7rS9tU1vW3xY5zA2bC4dE6fG8hJ0" + '"',
      'c="github_pat_' + "lM3nO5pQ7rS9tU1vW3xY5z" + "_" + "Q7rS9tU1vW3xY5zA2bC4dE6fG8hJ0kL2mN4pQ6rS8tV0wX2yZ4aB3dE5fG7" + '"',
      'd="GOCSPX-abcdefghijklmnopqrstuvwx"',
      'e="SG.' + "lM3nO5pQ7rS9tU1vW3xY5z" + "." + "Q7rS9tU1vW3xY5zA2bC4dE6fG8hJ0kL2mN4pQ6rS8tV" + '"',
    ].join("\n"));
    const ids = (await exposedSecrets.run(ctx(dir))).map((f) => f.id.split(":")[1]);
    for (const id of ["slack-token", "npm-token", "github-fine-grained-pat", "google-oauth-secret", "sendgrid-key"]) {
      assert.ok(ids.includes(id), `missing ${id}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ordinary minified code does not trip the new patterns", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec3-"));
  try {
    writeFileSync(join(dir, "app.js"), "const ghost=1;const box='xoxo';function sg(){return SG;}\nconst npmrc='registry';\n");
    const found = await exposedSecrets.run(ctx(dir));
    assert.equal(found.length, 0, "should not false-positive on ordinary code");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the OpenAI pattern does not fire on short sk- tokens in minified code", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec4-"));
  try {
    // a standalone sk- token of only 20 alnum chars (realistic minified noise)
    writeFileSync(join(dir, "app.js"), 'const c="sk-1a2b3c4d5e6f7g8h9i0j";\n');
    const found = await exposedSecrets.run(ctx(dir));
    assert.ok(!found.some((f) => f.id.includes("openai")), "20-char sk- token must not be reported");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a real-length OpenAI key is still detected", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec5-"));
  try {
    writeFileSync(join(dir, "app.js"), 'const k="sk-' + "lM3nO5pQ7rS9tU1vW3xY5zA2bC4dE6fG8hJ0kL2mN4pQ6rS8" + '";\n');
    const found = await exposedSecrets.run(ctx(dir));
    assert.ok(found.some((f) => f.id.includes("openai-key")), "48-char sk- key should be detected");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("placeholders that only look like keys are not findings", async () => {
  const { isPlaceholder } = await import("./exposed-secrets.js");
  for (const p of ["sk_live_xxxxxxxxxxxxxxxxxxxx", "sk_live_YOUR_SECRET_KEY_HERE_12", "ghp_000000000000000000000000000000000000", "sk-ant-api03-<your-key>-aaaaaaaaaa", "sk_test_EXAMPLEKEY1234567890ab"]) assert.ok(isPlaceholder(p), p);
  for (const k of ["sk_live_51BenchServerKey9x8y7z6w5v4u", "sk_live_ABCDEFGHIJKLMNOP1234", "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"]) assert.ok(!isPlaceholder(k), k);
});

test("decoded views: keys split, joined, base64-encoded, escaped or reversed are found once, with the decoding named", async () => {
  const { decodedViews } = await import("./exposed-secrets.js");
  const key = "sk_live_" + "51HiddenKeyAbcdefGhij0123";
  const b64 = Buffer.from(key).toString("base64");
  const esc = [...key].map((c) => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  const rev = [...key].reverse().join("");
  const views = decodedViews(`a = "sk_li" + 've_51HiddenKeyAbcdefGhij0123';\nb = ["sk_live_51Hidden", "KeyAbcdefGhij0123"].join("");\nc = atob("${b64}");\nd = "${esc}";\ne = "${rev}".split("").reverse().join("");`);
  assert.deepEqual(views.map((v) => [v.method, v.text]), [
    ["string concatenation", key], ["array join", key], ["base64 (atob)", key], ["escaped characters", key], ["reversed string", key],
  ]);
  const dir = mkdtempSync(join(tmpdir(), "crenel-dec-"));
  try {
    writeFileSync(join(dir, "app.js"), `const k = "sk_li" + "ve_51HiddenKeyAbcdefGhij0123";\nconst plain = "sk_live_51PlainKeyAbcdefGhij0123" + "";\nconst ph = "sk_live_" + "xxxxxxxxxxxxxxxxxxxx";\nconst label = "Price: " + "12";`);
    const f = await exposedSecrets.run({ scope: undefined as never, projectDir: dir, options: {}, log: () => {} });
    assert.deepEqual(f.map((x) => x.id).sort(), ["exposed-secrets:stripe-secret:app.js:1:decoded", "exposed-secrets:stripe-secret:app.js:2"]);
    const hidden = f.find((x) => x.id.endsWith(":decoded"))!;
    assert.match(hidden.title, /hidden by string concatenation/);
    assert.equal(hidden.state, "proven");
    assert.doesNotMatch(JSON.stringify(f), /51HiddenKeyAbcdefGhij0123/, "the key is redacted");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
