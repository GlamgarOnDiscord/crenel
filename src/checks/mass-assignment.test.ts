import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { massAssignment, plannedMass } from "./mass-assignment.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";
import { generateRegressionFile } from "../generate/tests.js";

// /api/me: mode "assign" copies the body (the bug), "allowlist" keeps only name,
// "strict" answers 400 to any unknown field. /api/me/locked never lets role go back.
function api(mode: "assign" | "allowlist" | "strict", { sticky = false } = {}) {
  const me: Record<string, unknown> = { id: "user_a", name: "Ann", role: "member", billing: { plan: "free" } };
  const seen: string[] = [];
  const srv = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      seen.push(`${req.method} ${req.url}`);
      res.setHeader("content-type", "application/json");
      if (req.headers.authorization !== "Bearer tok-a") { res.statusCode = 401; return res.end("{}"); }
      if (req.method === "GET") return res.end(JSON.stringify(me));
      const b = JSON.parse(raw || "{}") as Record<string, unknown>;
      if (mode === "strict" && Object.keys(b).some((k) => k !== "name")) { res.statusCode = 400; return res.end('{"error":"unknown field"}'); }
      if (mode === "allowlist") { if (typeof b.name === "string") me.name = b.name; return res.end(JSON.stringify(me)); }
      for (const [k, v] of Object.entries(b)) {
        if (sticky && k === "role" && me.role === "admin") continue;
        me[k] = k === "billing" ? { ...(me.billing as object), ...(v as object) } : v;
      }
      res.end(JSON.stringify(me));
    });
  });
  return { srv, me, seen };
}
async function listen(s: ReturnType<typeof api>) {
  await new Promise<void>((r) => s.srv.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(s.srv.address() as AddressInfo).port}`;
}
const ctx = (base: string, opts: Record<string, unknown>, active = true): CheckContext => ({
  scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: active }),
  projectDir: ".", stagingUrl: base, log: () => {},
  options: { "authz-matrix": { accounts: { a: { token: "tok-a" } } }, "mass-assignment": { enabled: true, ...opts } },
});
const me = { name: "profile", path: "/api/me", method: "PATCH", fields: { role: "admin", "billing.plan": "enterprise" }, body: { name: "Ann" } };

test("mass-assignment: role and a nested plan accepted from the body are proven, then restored", async () => {
  const s = api("assign"); const base = await listen(s);
  try {
    const f = await massAssignment.run(ctx(base, { targets: [me] }));
    const p = f.filter((x) => x.state === "proven");
    assert.equal(p.length, 1);
    assert.equal(p[0]!.id, "mass-assignment:profile:PATCH:role,billing.plan");
    assert.equal(p[0]!.severity, "critical", "role is a privilege");
    assert.match(p[0]!.description, /every field restored/);
    assert.equal(s.me.role, "member");
    assert.deepEqual(s.me.billing, { plan: "free" });
    assert.match(f.find((x) => x.id === "mass-assignment:writes")!.proof!.evidence!, /PATCH .*\/api\/me as A .*restored/);
  } finally { s.srv.close(); }
});

test("mass-assignment: an allowlist and a strict schema are clean, and nothing needs restoring", async () => {
  for (const mode of ["allowlist", "strict"] as const) {
    const s = api(mode); const base = await listen(s);
    try {
      const f = await massAssignment.run(ctx(base, { targets: [me] }));
      assert.equal(f.filter((x) => x.state === "proven").length, 0, mode);
      assert.match(f.find((x) => x.id === "mass-assignment:writes")!.proof!.evidence!, /nothing to restore/, mode);
      assert.equal(s.me.role, "member");
    } finally { s.srv.close(); }
  }
});

test("mass-assignment: a field that cannot be put back is reported as not restored", async () => {
  const s = api("assign", { sticky: true }); const base = await listen(s);
  try {
    const f = await massAssignment.run(ctx(base, { targets: [{ ...me, fields: { role: "admin" } }] }));
    const p = f.find((x) => x.state === "proven")!;
    assert.match(p.description, /NOT restored: role should be "member"/);
    assert.match(f.find((x) => x.id === "mass-assignment:writes")!.title, /1 change\(s\) NOT restored/);
  } finally { s.srv.close(); }
});

test("mass-assignment: a value A already has is not tried; a field the read never shows is noted", async () => {
  const s = api("assign"); const base = await listen(s);
  try {
    const f = await massAssignment.run(ctx(base, { targets: [{ ...me, fields: { role: "member", credits: 999 } }] }));
    const notes = f.find((x) => x.id === "mass-assignment:writes")!.description;
    assert.match(notes, /role is already "member"/);
    // credits was not in the read before, the server stored it: it shows after, so it is proven.
    assert.equal(f.find((x) => x.state === "proven")!.severity, "high");
  } finally { s.srv.close(); }
});

test("mass-assignment: off unless enabled, refused without allowActiveTesting, A's own object only", async () => {
  const s = api("assign"); const base = await listen(s);
  try {
    const off = ctx(base, { targets: [me] });
    (off.options["mass-assignment"] as Record<string, unknown>).enabled = false;
    assert.deepEqual(await massAssignment.run(off), []);
    await assert.rejects(() => massAssignment.run(ctx(base, { targets: [me] }, false)), /allowActiveTesting is off/);
    assert.equal(s.seen.length, 0);
    await massAssignment.run(ctx(base, { targets: [me] }));
    assert.ok(s.seen.every((r) => r.endsWith(" /api/me")), "only the declared route");
  } finally { s.srv.close(); }
});

test("mass-assignment: regression test and gate plan", async () => {
  const s = api("assign"); const base = await listen(s);
  try {
    const out = generateRegressionFile(await massAssignment.run(ctx(base, { targets: [me] })));
    assert.equal((out.match(/\btest\(/g) ?? []).length, 1);
    assert.match(out, /not\.toEqual\("admin"\)/);
    assert.deepEqual(plannedMass({ "mass-assignment": { enabled: true, targets: [me] } }, "https://s.test").map((p) => `${p.method} ${p.url}`), ["PATCH https://s.test/api/me", "GET https://s.test/api/me"]);
  } finally { s.srv.close(); }
});
