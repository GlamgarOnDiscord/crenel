import { test } from "node:test";
import assert from "node:assert/strict";
import { userEnumOracle } from "./userenum.js";

const o = (status: number, body: string) => ({ status, body });

test("user-enum: existing differs by status, two absent match -> enum", () => {
  const r = userEnumOracle({ existingName: "alice", absentName1: "zzx1", absentName2: "qqy2",
    existing: o(401, '{"error":"wrong password"}'), absent1: o(404, '{"error":"no such user"}'), absent2: o(404, '{"error":"no such user"}') });
  assert.equal(r.verdict, "enum");
});

test("user-enum: existing differs by body phrase -> enum", () => {
  const r = userEnumOracle({ existingName: "alice", absentName1: "zzx1", absentName2: "qqy2",
    existing: o(200, '{"message":"invalid password"}'), absent1: o(200, '{"message":"account not found"}'), absent2: o(200, '{"message":"account not found"}') });
  assert.equal(r.verdict, "enum");
});

test("user-enum: an endpoint that only echoes the username is not a leak", () => {
  const r = userEnumOracle({ existingName: "alice", absentName1: "zzx1", absentName2: "qqy2",
    existing: o(401, '{"user":"alice","error":"login failed"}'), absent1: o(401, '{"user":"zzx1","error":"login failed"}'), absent2: o(401, '{"user":"qqy2","error":"login failed"}') });
  assert.equal(r.verdict, "denied");
});

test("user-enum: two absent answers differing -> lead (noisy)", () => {
  const r = userEnumOracle({ existingName: "alice", absentName1: "zzx1", absentName2: "qqy2",
    existing: o(401, "x"), absent1: o(404, "a"), absent2: o(500, "b") });
  assert.equal(r.verdict, "lead");
});

test("user-enum: same answer for existing and absent -> denied", () => {
  const r = userEnumOracle({ existingName: "alice", absentName1: "zzx1", absentName2: "qqy2",
    existing: o(401, "wrong credentials"), absent1: o(401, "wrong credentials"), absent2: o(401, "wrong credentials") });
  assert.equal(r.verdict, "denied");
});
