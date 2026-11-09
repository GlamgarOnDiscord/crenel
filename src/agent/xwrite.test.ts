import { test } from "node:test";
import assert from "node:assert/strict";
import { crossWriteOracle } from "./xwrite.js";

const r = (status: number, o: unknown = {}) => ({ status, body: JSON.stringify(o) });

test("cross-write DELETE: gone only after the attacker's delete -> written; kept -> denied; gone after anonymous -> anon-written", () => {
  assert.equal(crossWriteOracle({ method: "DELETE", before: r(200), afterAnon: r(200), attacker: r(204), after: r(404) }).verdict, "written");
  assert.equal(crossWriteOracle({ method: "DELETE", before: r(200), afterAnon: r(200), attacker: r(403), after: r(200) }).verdict, "denied");
  assert.equal(crossWriteOracle({ method: "DELETE", before: r(200), afterAnon: r(404), attacker: r(204), after: r(404) }).verdict, "anon-written");
  assert.equal(crossWriteOracle({ method: "DELETE", before: r(404), afterAnon: r(404), attacker: r(204), after: r(404) }).verdict, "lead", "the owner never read it");
});

test("cross-write PUT: the field takes the attacker's value only after the attacker's write -> written", () => {
  const b = (q: number) => r(200, { data: { id: 1, quantity: q } });
  assert.equal(crossWriteOracle({ method: "PUT", field: "quantity", value: 9, before: b(1), afterAnon: b(1), attacker: r(200), after: b(9) }).verdict, "written");
  assert.equal(crossWriteOracle({ method: "PUT", field: "quantity", value: 9, before: b(1), afterAnon: b(1), attacker: r(403), after: b(1) }).verdict, "denied");
  assert.equal(crossWriteOracle({ method: "PUT", field: "quantity", value: 1, before: b(1), afterAnon: b(1), attacker: r(200), after: b(1) }).verdict, "lead", "no change possible to see");
  assert.equal(crossWriteOracle({ method: "PATCH", field: "quantity", value: 9, before: b(1), afterAnon: b(9), attacker: r(200), after: b(9) }).verdict, "anon-written");
});
