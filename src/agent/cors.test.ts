import { test } from "node:test";
import assert from "node:assert/strict";
import { corsOracle } from "./cors.js";

const O1 = "https://crenel-evil-a.example", O2 = "https://crenel-attacker-b.test";

test("cors: reflects both attacker origins with credentials -> proven high", () => {
  const v = corsOracle({ o1: O1, r1: { acao: O1, acac: "true" }, o2: O2, r2: { acao: O2, acac: "true" } });
  assert.equal(v.verdict, "proven");
  assert.equal(v.ceiling, "high");
});

test("cors: ACAO null with credentials -> proven high", () => {
  const v = corsOracle({ o1: O1, r1: { acao: "null", acac: "true" }, o2: O2, r2: { acao: "null", acac: "true" } });
  assert.equal(v.verdict, "proven");
});

test("cors: reflects both but no credentials -> lead", () => {
  const v = corsOracle({ o1: O1, r1: { acao: O1, acac: null }, o2: O2, r2: { acao: O2, acac: null } });
  assert.equal(v.verdict, "lead");
});

test("cors: wildcard with credentials -> lead (browsers reject)", () => {
  const v = corsOracle({ o1: O1, r1: { acao: "*", acac: "true" }, o2: O2, r2: { acao: "*", acac: "true" } });
  assert.equal(v.verdict, "lead");
});

test("cors: only one origin reflected (allowlist or pattern) -> a lead, never proven", () => {
  const v = corsOracle({ o1: O1, r1: { acao: O1, acac: "true" }, o2: O2, r2: { acao: "https://trusted.app", acac: "true" } });
  assert.equal(v.verdict, "lead");
});

test("cors: credentials on only one of the two responses -> not proven", () => {
  const v = corsOracle({ o1: O1, r1: { acao: O1, acac: "true" }, o2: O2, r2: { acao: O2, acac: null } });
  assert.equal(v.verdict, "lead");
});

test("cors: Allow-Credentials must be the exact literal true (TRUE does not enable credentials)", () => {
  const v = corsOracle({ o1: O1, r1: { acao: O1, acac: "TRUE" }, o2: O2, r2: { acao: O2, acac: "True" } });
  assert.equal(v.verdict, "lead");
});

test("cors: no ACAO header -> denied", () => {
  const v = corsOracle({ o1: O1, r1: { acao: null, acac: null }, o2: O2, r2: { acao: null, acac: null } });
  assert.equal(v.verdict, "denied");
});
