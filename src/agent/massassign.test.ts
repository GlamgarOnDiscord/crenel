import { test } from "node:test";
import assert from "node:assert/strict";
import { massAssignOracle, fieldValue, canonical, buildBody } from "./massassign.js";

test("fieldValue reads scalars at any depth", () => {
  assert.equal(fieldValue('{"role":"user"}', "role"), "user");
  assert.equal(fieldValue('{"user":{"isAdmin":false}}', "isAdmin"), "false");
  assert.equal(fieldValue('{"data":[{"credits":10}]}', "credits"), "10");
  assert.equal(fieldValue('{"a":1}', "role"), undefined);
  assert.equal(fieldValue("not json", "role"), undefined);
  assert.equal(fieldValue('{"role":{"x":1}}', "role"), undefined); // object value is not scalar
});

test("canonical normalizes types to what fieldValue returns", () => {
  assert.equal(canonical(true), "true");
  assert.equal(canonical(42), "42");
  assert.equal(canonical("admin"), "admin");
  assert.equal(canonical(null), "null");
});

const read = (field: string, v: unknown) => ({ status: 200, body: JSON.stringify({ [field]: v }) });

test("mass-assignment: field takes the injected value, control stays -> set", () => {
  const r = massAssignOracle({ field: "role", injected: "admin", baseline: read("role", "user"), control: read("role", "user"), injectedRead: read("role", "admin") });
  assert.equal(r.verdict, "set");
});

test("mass-assignment: boolean escalation proven", () => {
  const r = massAssignOracle({ field: "isAdmin", injected: true, baseline: read("isAdmin", false), control: read("isAdmin", false), injectedRead: read("isAdmin", true) });
  assert.equal(r.verdict, "set");
});

test("mass-assignment: field ignored (unchanged) -> lead, not proven", () => {
  const r = massAssignOracle({ field: "role", injected: "admin", baseline: read("role", "user"), control: read("role", "user"), injectedRead: read("role", "user") });
  assert.equal(r.verdict, "lead");
});

test("mass-assignment: control moved the field -> not isolated, lead", () => {
  const r = massAssignOracle({ field: "role", injected: "admin", baseline: read("role", "user"), control: read("role", "editor"), injectedRead: read("role", "admin") });
  assert.equal(r.verdict, "lead");
});

test("mass-assignment: injected equals current value -> lead", () => {
  const r = massAssignOracle({ field: "role", injected: "user", baseline: read("role", "user"), control: read("role", "user"), injectedRead: read("role", "user") });
  assert.equal(r.verdict, "lead");
});

test("mass-assignment: field absent from baseline -> cannot prove", () => {
  const r = massAssignOracle({ field: "role", injected: "admin", baseline: { status: 200, body: '{"name":"x"}' }, control: { status: 200, body: '{"name":"x"}' }, injectedRead: { status: 200, body: '{"name":"x","role":"admin"}' } });
  assert.equal(r.verdict, "lead");
});

test("mass-assignment: baseline not readable -> denied", () => {
  const r = massAssignOracle({ field: "role", injected: "admin", baseline: { status: 403, body: "" }, control: read("role", "user"), injectedRead: read("role", "admin") });
  assert.equal(r.verdict, "denied");
});

test("buildBody: json and form, with and without extra", () => {
  const j = buildBody({ name: "x" }, { role: "admin" }, "json");
  assert.equal(j.contentType, "application/json");
  assert.deepEqual(JSON.parse(j.body), { name: "x", role: "admin" });
  const f = buildBody({ name: "x" }, null, "form");
  assert.equal(f.contentType, "application/x-www-form-urlencoded");
  assert.equal(new URLSearchParams(f.body).get("name"), "x");
  assert.equal(new URLSearchParams(f.body).get("role"), null);
});
