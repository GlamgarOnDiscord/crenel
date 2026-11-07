import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { businessLogic, findHypotheses, callExtent } from "./business-logic.js";

test("callExtent: the closing paren of the call, strings skipped", () => {
  const s = `fetch("/a)", { body: ")" }) + x`;
  assert.equal(s.slice(0, callExtent(s, 5)), `fetch("/a)", { body: ")" })`);
});

test("findHypotheses: client-set amount, plan and role, Supabase update, admin routes", () => {
  const src = [
    `fetch("/api/checkout", { method: "POST", body: JSON.stringify({ items, amount: total * 100 }) })`,
    `axios.post("/api/profile", { name, plan: "pro" })`,
    `supabase.from("profiles").update({ role: "admin" }).eq("id", uid)`,
    `const r = await fetch("/api/admin/users")`,
    // minified
    `fetch("/api/credits/buy",{method:"POST",body:JSON.stringify({credits:n,unit_amount:500})})`,
  ].join("\n");
  const h = findHypotheses(src, "app.js").map((x) => `${x.kind}:${x.route}:${x.key}`);
  assert.deepEqual(h.sort(), [
    "payment:/api/checkout:amount", "payment:/api/credits/buy:unit_amount", "privilege:/api/credits/buy:credits",
    "privilege:/api/profile:plan", "privilege:supabase table profiles (update):role", "routes:/api/admin/users:", "routes:/api/credits/buy:",
  ].sort());
});

test("findHypotheses: decoys stay quiet", () => {
  const src = [
    `fetch("/api/subscribe", { method: "POST", body: JSON.stringify({ priceId: "price_1Pabc", price: "price_1Pabc" }) })`, // a Stripe price id
    `fetch("https://api.stripe.com/v1/charges", { method: "POST", body: "amount=100" })`, // not the app's route
    `fetch("/api/cart?amount=3")`, // a GET without body
    `React.createElement("div", { role: "button", onClick })`, // an ARIA role
    `app.post("/api/checkout", async (req, res) => { const amount = 100; res.json({ amount: amount }) })`, // a server route declaration
    `fetch("/api/team", { method: "POST", body: JSON.stringify({ name }) })`,
  ].join("\n");
  assert.deepEqual(findHypotheses(src, "app.js"), []);
});

test("business-logic: unproven hypotheses with a written test; server files are skipped", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-bl-"));
  try {
    mkdirSync(join(dir, "api"));
    writeFileSync(join(dir, "client.js"), `fetch("/api/checkout", { method: "POST", body: JSON.stringify({ amount }) });\nconst A = "/api/invites/accept";`);
    writeFileSync(join(dir, "api", "pay.js"), `fetch("/api/internal", { method: "POST", body: JSON.stringify({ amount: 5, role: "x" }) })`);
    const f = await businessLogic.run({ scope: undefined as never, projectDir: dir, options: {}, log: () => {} });
    assert.deepEqual(f.map((x) => x.id).sort(), ["business-logic:payment:/api/checkout:amount", "business-logic:routes"]);
    assert.ok(f.every((x) => x.state === "unproven"));
    assert.match(f.find((x) => x.id.includes("payment"))!.regressionHint!, /Crenel does not, it writes/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
