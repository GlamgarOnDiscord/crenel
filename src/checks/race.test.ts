import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { race, plannedRace } from "./race.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";
import { generateRegressionFile } from "../generate/tests.js";

// A single-use coupon worth 10 credits. "racy": check, await, then consume.
// "atomic": check-and-consume in one synchronous step. "idempotent": every
// request answers 200, only the first one counts.
function api(mode: "racy" | "atomic" | "idempotent") {
  const st = { used: 0, credits: 0, hits: 0 };
  const srv = createServer((req, res) => {
    req.resume();
    req.on("end", async () => {
      res.setHeader("content-type", "application/json");
      if (req.headers.authorization !== "Bearer tok-a") { res.statusCode = 401; return res.end("{}"); }
      if (req.method === "GET") return res.end(JSON.stringify({ wallet: { credits: st.credits } }));
      st.hits++;
      if (mode === "racy") {
        if (st.used >= 1) { res.statusCode = 409; return res.end('{"error":"used"}'); }
        await new Promise((r) => setTimeout(r, 30));
        st.used++; st.credits += 10; return res.end('{"ok":true}');
      }
      if (st.used >= 1) { res.statusCode = mode === "idempotent" ? 200 : 409; return res.end(mode === "idempotent" ? '{"ok":true,"already":true}' : '{"error":"used"}'); }
      st.used++; st.credits += 10; return res.end('{"ok":true}');
    });
  });
  return { srv, st };
}
async function listen(s: ReturnType<typeof api>) {
  await new Promise<void>((r) => s.srv.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(s.srv.address() as AddressInfo).port}`;
}
const ctx = (base: string, opts: Record<string, unknown>, active = true): CheckContext => ({
  scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: active }),
  projectDir: ".", stagingUrl: base, log: () => {},
  options: { "authz-matrix": { accounts: { a: { token: "tok-a" } } }, race: { enabled: true, ...opts } },
});
const coupon = { name: "coupon", path: "/api/coupons/redeem", body: { code: "WELCOME" }, max: 1, readPath: "/api/me", readField: "wallet.credits", perSuccess: 10 };

test("race: a check-then-consume handler is proven by responses and by the read; uses spent are reported", async () => {
  const s = api("racy"); const base = await listen(s);
  try {
    const f = await race.run(ctx(base, { targets: [coupon] }));
    const p = f.find((x) => x.state === "proven")!;
    assert.equal(p.id, "race:coupon:POST:/api/coupons/redeem");
    assert.equal(s.st.hits, 10, "one burst of the default 10, no retry");
    assert.ok(s.st.used > 1);
    assert.match(p.description, /Nothing was restored/);
    assert.match(f.find((x) => x.id === "race:writes")!.title, /NOT restored/);
  } finally { s.srv.close(); }
});

test("race: an atomic handler is clean; an idempotent 200 is never proven", async () => {
  const a = api("atomic"); const ba = await listen(a);
  try { assert.equal((await race.run(ctx(ba, { targets: [coupon] }))).filter((x) => x.check === "race" && !x.id.endsWith(":writes")).length, 0); } finally { a.srv.close(); }
  const i = api("idempotent"); const bi = await listen(i);
  try {
    const f = await race.run(ctx(bi, { targets: [coupon] }));
    assert.equal(f.filter((x) => x.state === "proven").length, 0, "the read shows one use: not a race");
    assert.equal(f.find((x) => x.id.startsWith("race:coupon"))?.state, "unproven");
  } finally { i.srv.close(); }
});

test("race: without a read it stays a lead; concurrency is capped at 25", async () => {
  const s = api("racy"); const base = await listen(s);
  try {
    const f = await race.run(ctx(base, { targets: [{ ...coupon, readPath: undefined, concurrency: 500 }] }));
    assert.equal(s.st.hits, 25);
    assert.equal(f.filter((x) => x.state === "proven").length, 0);
    assert.equal(f.find((x) => x.id.startsWith("race:coupon"))!.severity, "medium");
  } finally { s.srv.close(); }
});

test("race: off unless enabled, refused without allowActiveTesting, budget checked before the burst", async () => {
  const s = api("racy"); const base = await listen(s);
  try {
    const off = ctx(base, { targets: [coupon] });
    (off.options.race as Record<string, unknown>).enabled = false;
    assert.deepEqual(await race.run(off), []);
    await assert.rejects(() => race.run(ctx(base, { targets: [coupon] }, false)), /allowActiveTesting is off/);
    await race.run(ctx(base, { targets: [coupon], maxRequests: 5 }));
    assert.equal(s.st.hits, 0, "a burst that does not fit the budget is not started");
  } finally { s.srv.close(); }
});

test("race: regression test and gate plan", async () => {
  const s = api("racy"); const base = await listen(s);
  try {
    const out = generateRegressionFile(await race.run(ctx(base, { targets: [coupon] })));
    assert.match(out, /toBeLessThanOrEqual\(1\)/);
    assert.deepEqual(plannedRace({ race: { enabled: true, targets: [coupon] } }, "https://s.test").map((p) => p.method), ["POST", "GET"]);
  } finally { s.srv.close(); }
});
