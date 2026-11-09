import { test } from "node:test";
import assert from "node:assert/strict";
import { bflaOracle } from "./bfla.js";
const o = (s: number, b = "") => ({ status: s, body: b });

test("bfla read: normal gets the privileged view, anon+control denied -> bfla", () => {
  const admin = o(200, '{"users":[1,2,3],"secret":"x"}');
  assert.equal(bflaOracle({ isRead: true, privileged: admin, normal: admin, anon: o(403), control: o(404) }).verdict, "bfla");
});
test("bfla write: both 2xx, anon+control denied -> bfla", () => {
  assert.equal(bflaOracle({ isRead: false, privileged: o(200), normal: o(200), anon: o(401), control: o(404) }).verdict, "bfla");
});
test("bfla: normal refused -> denied (check holds)", () => {
  assert.equal(bflaOracle({ isRead: true, privileged: o(200, "a"), normal: o(403), anon: o(403), control: o(404) }).verdict, "denied");
});
test("bfla: anon reaches it -> lead (public)", () => {
  assert.equal(bflaOracle({ isRead: true, privileged: o(200, "a"), normal: o(200, "a"), anon: o(200, "a"), control: o(404) }).verdict, "lead");
});
test("bfla: control 2xx -> lead (not discriminating)", () => {
  assert.equal(bflaOracle({ isRead: false, privileged: o(200), normal: o(200), anon: o(401), control: o(200) }).verdict, "lead");
});
test("bfla read: normal gets a different (personalized) body -> lead", () => {
  assert.equal(bflaOracle({ isRead: true, privileged: o(200, '{"users":[1,2,3,4,5,6,7,8,9]}'), normal: o(200, '{"users":[]}'), anon: o(403), control: o(404) }).verdict, "lead");
});
