import { test } from "node:test";
import assert from "node:assert/strict";
import { reuseOracle } from "./reuse.js";

const applied = { status: 200, body: '{"valid":true,"discount":10}' };
const rejected = { status: 404, body: '{"valid":false}' };
const M = ["discount"];

test("reuse: same artifact applied twice while invalid is rejected -> reused", () => {
  const r = reuseOracle({ first: applied, second: applied, control: rejected, successMarkers: M });
  assert.equal(r.verdict, "reused");
});

test("reuse: second application rejected -> lead (properly single-use)", () => {
  const r = reuseOracle({ first: applied, second: rejected, control: rejected, successMarkers: M });
  assert.equal(r.verdict, "lead");
});

test("reuse: invalid artifact also succeeds -> lead, not a reuse proof", () => {
  const r = reuseOracle({ first: applied, second: applied, control: applied, successMarkers: M });
  assert.equal(r.verdict, "lead");
});

test("reuse: first never succeeded -> denied", () => {
  const r = reuseOracle({ first: rejected, second: rejected, control: rejected, successMarkers: M });
  assert.equal(r.verdict, "denied");
});

test("reuse: no success marker -> lead", () => {
  const r = reuseOracle({ first: applied, second: applied, control: rejected, successMarkers: [] });
  assert.equal(r.verdict, "lead");
});

test("reuse: a marker inside a refusal on the second try is not a reuse", () => {
  const r = reuseOracle({ first: { status: 200, body: '{"discount":10}' }, second: { status: 200, body: '{"message":"discount already used"}' }, control: { status: 404, body: "no" }, successMarkers: ["discount"] });
  assert.equal(r.verdict, "lead");
});
