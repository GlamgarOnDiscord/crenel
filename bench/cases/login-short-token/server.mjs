// A billing API behind a JSON login that issues short-lived JWTs (30 s), the
// common shape of a real SaaS API: no long-lived token exists to paste into a
// config. Invoices are login-gated but miss the ownership check (any logged-in
// user reads any customer's invoice). Payment methods do check ownership: a
// decoy that must not be flagged. No session: 401. Unknown id: 404.
import { createHmac, randomBytes } from "node:crypto";
import { json } from "../../lib/tenant-app.mjs";
import { createServer } from "node:http";

const KEY = randomBytes(32);
const USERS = { "ana@acme.example": "fixture-pw-ana", "ben@globex.example": "fixture-pw-ben" };
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const sign = (sub) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, exp: Math.floor(Date.now() / 1000) + 30 }); return `${h}.${p}.${createHmac("sha256", KEY).update(`${h}.${p}`).digest("base64url")}`; };
function who(req) {
  const t = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
  if (!t) return null;
  const [h, p, s] = t.split(".");
  if (!h || !p || createHmac("sha256", KEY).update(`${h}.${p}`).digest("base64url") !== s) return null;
  const claims = JSON.parse(Buffer.from(p, "base64url").toString());
  return claims.exp > Date.now() / 1000 ? claims.sub : null;
}
const invoices = { inv_7f3a: { id: "inv_7f3a", customer: "ana@acme.example", total: 120 }, inv_9c1d: { id: "inv_9c1d", customer: "ben@globex.example", total: 4300 } };
const cards = { pm_51aa: { id: "pm_51aa", owner: "ana@acme.example", last4: "4242" }, pm_77bb: { id: "pm_77bb", owner: "ben@globex.example", last4: "1881" } };

export default () => createServer((req, res) => {
  let raw = "";
  req.on("data", (d) => { raw += d; });
  req.on("end", () => {
    const u = new URL(req.url, "http://x");
    if (req.method === "POST" && u.pathname === "/auth/login") {
      let b = {}; try { b = JSON.parse(raw || "{}"); } catch {}
      if (!USERS[b.email] || USERS[b.email] !== b.password) return json(res, 401, { error: "invalid credentials" });
      return json(res, 200, { data: { accessToken: sign(b.email), expiresIn: 30 } });
    }
    const m = /^\/api\/(invoices|payment-methods)\/([^/]+)$/.exec(u.pathname);
    if (req.method === "GET" && m) {
      const me = who(req);
      if (!me) return json(res, 401, { error: "unauthorized" });
      if (m[1] === "invoices") { const inv = invoices[m[2]]; return inv ? json(res, 200, inv) : json(res, 404, { error: "not found" }); }
      const pm = cards[m[2]];
      return pm && pm.owner === me ? json(res, 200, pm) : json(res, 404, { error: "not found" });
    }
    json(res, 404, { error: "not found" });
  });
});
