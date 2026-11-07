import { test } from "node:test";
import assert from "node:assert/strict";
import { authzMatrix } from "./authz-matrix.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(partial: Partial<CheckContext> & { options?: Record<string, unknown> } = {}): CheckContext {
  return {
    scope: partial.scope ?? new Scope({ allowedHosts: [] }),
    projectDir: partial.projectDir ?? "/tmp/x",
    stagingUrl: partial.stagingUrl,
    options: partial.options ?? {},
    log: () => {},
  };
}

const RESOURCES = {
  "authz-matrix": {
    resources: [{ name: "project", path: "/api/projects/:id", methods: ["GET", "DELETE"] }],
    accounts: { a: { label: "A", token: "tok" }, b: { label: "B", owns: { project: ["p_b_1"] } } },
  },
};

test("no resources declared yields no findings", async () => {
  const found = await authzMatrix.run(ctx());
  assert.equal(found.length, 0);
});

test("offline, it emits one unproven plan with a generated test matrix", async () => {
  const found = await authzMatrix.run(ctx({ options: RESOURCES }));
  assert.equal(found.length, 1);
  const f = found[0];
  assert.ok(f);
  assert.equal(f.id, "authz-matrix:offline-plan");
  assert.equal(f.state, "unproven");
  assert.equal(f.severity, "medium");
  // the plan carries a runnable test that names the resource and both methods
  const gen = f.regressionHint ?? "";
  assert.match(gen, /\/api\/projects\/:id/);
  assert.match(gen, /GET another account/);
  assert.match(gen, /DELETE another account/);
  assert.match(gen, /\[401, 403, 404\]/);
});

test("a declared staging probe is refused unless active testing is enabled", async () => {
  // stagingUrl + token + cases => it would probe, but the scope gate must hold.
  const scope = new Scope({ allowedHosts: ["staging.example.com"], allowActiveTesting: false });
  await assert.rejects(
    () => authzMatrix.run(ctx({ scope, stagingUrl: "https://staging.example.com", options: RESOURCES })),
    /active/i,
  );
});
