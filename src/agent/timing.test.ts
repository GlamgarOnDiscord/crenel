import { test } from "node:test";
import assert from "node:assert/strict";
import { timingOracle } from "./timing.js";

test("timing: slow clearly separated and above the margin -> proven", () => {
  assert.equal(timingOracle({ fast: [40, 55, 48], slow: [1560, 1600, 1545], sleepMs: 1500 }).verdict, "proven");
});
test("timing: overlap -> denied", () => {
  assert.equal(timingOracle({ fast: [40, 1600, 48], slow: [1560, 1600, 1545], sleepMs: 1500 }).verdict, "denied");
});
test("timing: separated but below the margin -> lead", () => {
  assert.equal(timingOracle({ fast: [40, 55, 48], slow: [300, 320, 310], sleepMs: 1500 }).verdict, "lead");
});
test("timing: too few samples -> lead", () => {
  assert.equal(timingOracle({ fast: [40, 55], slow: [1560, 1600], sleepMs: 1500 }).verdict, "lead");
});
test("timing: a uniformly slow endpoint (no delta) -> overlap denied", () => {
  assert.equal(timingOracle({ fast: [900, 1100, 1000], slow: [950, 1050, 1000], sleepMs: 1500 }).verdict, "denied");
});
