import { test } from "node:test";
import assert from "node:assert/strict";
import { privEscOracle } from "./privesc.js";
const o = (s: number) => ({ status: s, body: "" });

test("priv-esc: denied twice then allowed after the write -> escalated", () => {
  assert.equal(privEscOracle({ gateBefore1: o(403), gateBefore2: o(403), gateAfter: o(200), gateAnon: o(401) }).verdict, "escalated");
});
test("priv-esc: still denied after -> denied", () => {
  assert.equal(privEscOracle({ gateBefore1: o(403), gateBefore2: o(403), gateAfter: o(403), gateAnon: o(401) }).verdict, "denied");
});
test("priv-esc: reachable before the write -> denied (no boundary crossed)", () => {
  assert.equal(privEscOracle({ gateBefore1: o(200), gateBefore2: o(200), gateAfter: o(200), gateAnon: o(401) }).verdict, "denied");
});
test("priv-esc: a gate that anon can reach is not a boundary -> lead", () => {
  assert.equal(privEscOracle({ gateBefore1: o(403), gateBefore2: o(403), gateAfter: o(200), gateAnon: o(200) }).verdict, "lead");
});
test("priv-esc: unstable denial before -> lead", () => {
  assert.equal(privEscOracle({ gateBefore1: o(403), gateBefore2: o(404), gateAfter: o(200), gateAnon: o(401) }).verdict, "lead");
});
