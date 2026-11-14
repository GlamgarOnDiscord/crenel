import { test } from "node:test";
import assert from "node:assert/strict";
import { run } from "./runner.js";
import type { Check, CheckContext, Finding } from "./types.js";
import { ConfigSchema } from "./config.js";

const config = ConfigSchema.parse({ project: "t", scope: { allowedHosts: [] } });

function check(name: string, impl: (ctx: CheckContext) => Finding[] | Promise<Finding[]>): Check {
  return { name, title: name, readOnly: true, run: (ctx) => Promise.resolve(impl(ctx)) };
}

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "f", check: "ok", title: "t", severity: "high", state: "proven",
  location: "l", description: "d", remediation: "r", ...over,
});

test("a passing check contributes findings and is listed in checksRun", async () => {
  const r = await run(config, "x.yaml", {}, [check("ok", () => [finding()])]);
  assert.equal(r.findings.length, 1);
  assert.deepEqual(r.checksRun, ["ok"]);
  assert.equal(r.errors.length, 0);
});

test("a throwing check goes to errors, not findings, and does not sink the run", async () => {
  const r = await run(config, "x.yaml", {}, [
    check("boom", () => { throw new Error("kaboom"); }),
    check("ok", () => [finding({ id: "g", check: "ok" })]),
  ]);
  assert.equal(r.findings.length, 1, "the healthy check still ran");
  assert.deepEqual(r.checksRun, ["ok"], "the thrown check is not marked as run");
  assert.equal(r.errors.length, 1);
  assert.equal(r.errors[0]!.check, "boom");
  assert.match(r.errors[0]!.message, /kaboom/);
});

test("a check that runs but finds nothing is still counted as run", async () => {
  const r = await run(config, "x.yaml", {}, [check("quiet", () => [])]);
  assert.deepEqual(r.checksRun, ["quiet"]);
  assert.equal(r.findings.length, 0);
  assert.equal(r.errors.length, 0);
});

test("checks in one run share reconnaissance, but separate runs do not", async () => {
  const seen: Map<string, Promise<import("./net.js").SafeResponse>>[] = [];
  const inspect = (name: string) => check(name, (ctx) => {
    assert.ok(ctx.recon, "the runner provides a per-run reconnaissance map");
    seen.push(ctx.recon!);
    return [];
  });
  await run(config, "x.yaml", {}, [inspect("a"), inspect("b")]);
  await run(config, "x.yaml", {}, [inspect("c")]);
  assert.equal(seen[0], seen[1]);
  assert.notEqual(seen[1], seen[2]);
});
