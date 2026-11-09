import { test } from "node:test";
import assert from "node:assert/strict";
import { ATTACH_MAX_CHARS, ATTACH_MAX_FILES, PROMPT_MAX, looksBinary, refuseByType, tooLong } from "./attachments.ts";
import { DEMO_SUGGESTIONS, suggestionsFor, taskIdOf, taskRoute } from "./runs.ts";
import type { AgentEvent } from "./types.ts";

test("tooLong: the user's text and the files have their own limits, as on the server", () => {
  assert.equal(tooLong("court", [{ name: "f.txt", text: "x".repeat(PROMPT_MAX) }]), null, "a file can be longer than a message");
  assert.match(tooLong("p".repeat(PROMPT_MAX + 1), []) ?? "", /Message trop long/);
  assert.match(tooLong("p", [{ name: "f.txt", text: "x".repeat(ATTACH_MAX_CHARS + 1) }]) ?? "", /trop longs/);
  assert.match(tooLong("p", Array.from({ length: ATTACH_MAX_FILES + 1 }, (_, i) => ({ name: `f${i}`, text: "x" }))) ?? "", /au plus/);
});

test("refuseByType and looksBinary: text passes, images and binaries are refused", () => {
  assert.equal(refuseByType({ name: "app.ts", type: "" }), null);
  assert.equal(refuseByType({ name: "notes", type: "text/plain" }), null);
  assert.equal(refuseByType({ name: ".env", type: "" }), null);
  assert.match(refuseByType({ name: "shot.png", type: "image/png" }) ?? "", /images/);
  assert.match(refuseByType({ name: "a.bin", type: "application/octet-stream" }) ?? "", /binaire/);
  assert.equal(looksBinary("const a = 1;\n"), false);
  assert.equal(looksBinary("PK\u0003\u0004\u0000\u0000"), true);
});

const tool = (findings: { text: string; state: "proven" | "lead" | "fixed" }[]): AgentEvent =>
  ({ kind: "tool", tool: "scan.secrets", args: "", input: "", lines: [], dur: "1 s", findings: findings.map((f) => ({ sev: "high", ...f })) }) as AgentEvent;

test("suggestionsFor: derived from the run's findings, never the demo text", () => {
  assert.deepEqual(suggestionsFor([]), ["/scan"]);
  assert.deepEqual(suggestionsFor([tool([{ text: "Piste A", state: "lead" }])]), ["/explain Piste A", "/scan"]);
  assert.deepEqual(suggestionsFor([tool([{ text: "Piste A", state: "lead" }, { text: "Clé exposée", state: "proven" }])]), ["/explain Clé exposée", "/test", "/scan"]);
  assert.ok(!suggestionsFor([tool([{ text: "x", state: "proven" }])]).some((s) => DEMO_SUGGESTIONS.includes(s)));
});

test("taskRoute and taskIdOf: a copied link reopens the same task", () => {
  assert.equal(taskRoute("r-1 2"), "/app/agent?task=r-1%202");
  assert.equal(taskIdOf(undefined, "?task=r-1%202"), "r-1 2");
  assert.equal(taskIdOf({ taskId: "r-9" }, "?task=r-1"), "r-9");
  assert.equal(taskIdOf(null, ""), undefined);
});
