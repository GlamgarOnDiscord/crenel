import { test } from "node:test";
import assert from "node:assert/strict";
import { deriveMarkers, identityValues } from "./markers.js";

test("identityValues: identity fields of the account object, most specific first", () => {
  assert.deepEqual(identityValues(JSON.stringify({ user: { id: 7, email: "a@x.test", name: "A" } })), ["a@x.test", "7"]);
  assert.deepEqual(identityValues("not json"), []);
  assert.deepEqual(identityValues(JSON.stringify({ items: [{ id: "x1234567" }] })), [], "a list is not the account");
});

test("deriveMarkers: a value only that account's read carries becomes its marker", () => {
  const a = { status: 200, body: JSON.stringify({ id: 1, email: "alice@corp.test", plan: "pro" }) };
  const b = { status: 200, body: JSON.stringify({ id: 2, email: "bob@corp.test", plan: "pro" }) };
  assert.deepEqual(deriveMarkers({ a, b }, { status: 401, body: "{}" }), { a: "alice@corp.test", b: "bob@corp.test" });
});

test("deriveMarkers: short ids, shared values, identical reads and failed reads give no marker", () => {
  const same = { status: 200, body: JSON.stringify({ id: 12 }) };
  assert.deepEqual(deriveMarkers({ a: same, b: { status: 200, body: JSON.stringify({ id: 13 }) } }), {}, "a 2-digit id occurs by chance");
  const shared = JSON.stringify({ email: "team@corp.test" });
  assert.deepEqual(deriveMarkers({ a: { status: 200, body: shared }, b: { status: 200, body: shared } }), {}, "one identity for both");
  assert.deepEqual(deriveMarkers({ a: { status: 401, body: "{}" } }), {});
  const pub = { status: 200, body: JSON.stringify({ username: "public-demo" }) };
  assert.deepEqual(deriveMarkers({ a: pub }, pub), {}, "what anonymous gets is not the account's own");
});

test("tokenIdentity and ownerFieldValues: who a token is, and whose an object is", async () => {
  const { tokenIdentity, ownerFieldValues } = await import("./markers.js");
  const jwt = (p: unknown) => `h.${Buffer.from(JSON.stringify(p)).toString("base64url")}.s`;
  assert.deepEqual(tokenIdentity(jwt({ status: "ok", data: { id: 27, email: "bob@x.test" } })), ["27", "bob@x.test"]);
  assert.deepEqual(tokenIdentity(jwt({ sub: "u_1" })), ["u_1"]);
  assert.deepEqual(tokenIdentity("opaque-token"), []);
  assert.deepEqual(ownerFieldValues(JSON.stringify({ data: { id: 7, UserId: 27, coupon: null } })), ["27"]);
  assert.deepEqual(ownerFieldValues(JSON.stringify({ id: 1, name: "catalog item" })), []);
});
