import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { authInjection } from "./auth-injection.js";
import { Scope } from "../core/scope.js";

// A login that concatenates the email into its SQL: a tautology with a comment
// logs in (200 + token), anything else is 401. The check must prove the bypass;
// a safe login (always 401 unless exact match) must stay unproven.
function loginServer(vulnerable: boolean) {
  return createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      let email = "", password = "";
      try { const j = JSON.parse(b || "{}"); email = String(j.email ?? ""); password = String(j.password ?? ""); } catch { /* bad json */ }
      const json = (s: number, o: unknown) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
      // A tautology with a trailing comment bypasses auth on the vulnerable server.
      const bypass = vulnerable && /'\s*or\s*1=1--/i.test(email);
      if (bypass || (email === "admin@x.com" && password === "secret")) return json(200, { token: "ey.header.payload.sig" });
      return json(401, { error: "invalid credentials" });
    });
  });
}

async function run(vulnerable: boolean, active = true) {
  const srv = loginServer(vulnerable);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    return await authInjection.run({
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: active }),
      projectDir: ".", stagingUrl: base, log: () => {},
      options: { "auth-injection": { enabled: true, endpoints: [{ url: "/login", field: "email", template: { password: "x" } }] } },
    });
  } finally { srv.close(); }
}

test("auth-injection: a tautology login bypass is proven", async () => {
  const f = await run(true);
  assert.equal(f.length, 1);
  assert.equal(f[0]!.state, "proven");
  assert.match(f[0]!.title, /injection in email/);
});

test("auth-injection: a NoSQL operator bypass is proven and titled NoSQL (not SQL)", async () => {
  // A lookup that accepts a {$ne}/{$gt} operator returns a record where a scalar
  // would be rejected. The finding must read as NoSQL, never "SQL injection".
  const srv = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      let v: unknown; try { v = JSON.parse(b || "{}").code; } catch { v = undefined; }
      const json = (s: number, o: unknown) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
      // Only an always-true operator ($ne/$gt) matches a record; a scalar or an
      // always-false operator ($eq of a nonexistent value) does not.
      if (v && typeof v === "object" && ("$ne" in (v as object) || "$gt" in (v as object))) return json(200, { code: "REAL-COUPON", amount: 50 });
      return json(404, { error: "not found" });
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const f = await authInjection.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true }), projectDir: ".", stagingUrl: base, log: () => {},
      options: { "auth-injection": { enabled: true, endpoints: [{ url: "/coupon", field: "code", nosql: true }] } } });
    assert.equal(f.length, 1);
    assert.equal(f[0]!.state, "proven");
    assert.match(f[0]!.title, /NoSQL injection/);
    assert.doesNotMatch(f[0]!.title, /\bSQL injection/);
    assert.doesNotMatch(f[0]!.proof!.replay!, /OR 1=1/i);
  } finally { srv.close(); }
});

test("auth-injection: a safe login (no bypass) stays unproven", async () => {
  const f = await run(false);
  assert.equal(f.filter((x) => x.state === "proven").length, 0);
});

test("auth-injection: without active mode the check refuses to probe", async () => {
  await assert.rejects(() => run(true, false));
});
