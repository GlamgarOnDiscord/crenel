// DEMO ONLY. A deliberately vulnerable app on 127.0.0.1, so `crenel serve` has
// something real to probe without touching any host that is not yours.
//
//   node examples/vulnerable-app/server.mjs        # http://127.0.0.1:4580
//
// What is wrong with it, on purpose:
//   - GET /                 no CSP, no HSTS, a session cookie without flags
//   - GET /*.js, /*.map     the client bundle, with a server key and its source map
//   - GET /api/projects/:id any signed-in account reads any project (BOLA)
//   - GET /api/renders/:id  correct: only the owner, 404 otherwise
//   - GET /api/invoices/:id same BOLA as projects, but NOT declared in the live
//                           config: `crenel tools katana` finds it from the
//                           links on / and suggests adding it to the matrix
//   - /rest/v1/*            a fake Supabase PostgREST: `profiles` has no RLS
//                           (readable with the public anon key), `notes` has RLS
//
// Test accounts: Bearer demo-token-a (tenant A), demo-token-b (tenant B).

import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";

const PORT = Number(process.env.PORT ?? 4580);
const ANON = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRlbW8iLCJyb2xlIjoiYW5vbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.ZGVtby1zaWduYXR1cmUtbm90LXJlYWw";
const ACCOUNTS = { "demo-token-a": "acct_a_demo", "demo-token-b": "acct_b_demo" };
const PROJECTS = {
  proj_a_1: { id: "proj_a_1", owner: "acct_a_demo", name: "A's launch plan" },
  proj_b_1: { id: "proj_b_1", owner: "acct_b_demo", name: "B's roadmap", budget: 42000 },
};
const RENDERS = { rnd_b_1: { id: "rnd_b_1", owner: "acct_b_demo", status: "done" } };
const INVOICES = { inv_b_1: { id: "inv_b_1", owner: "acct_b_demo", total: 1200 } };

const json = (res, status, body, headers = {}) => {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
};

const server = createServer((req, res) => {
  // A scanner sends odd paths ("///x"): parse them as a path, never let them crash the demo.
  let url;
  try { url = new URL(`http://127.0.0.1:${PORT}/${String(req.url).replace(/^\/+/, "")}`); }
  catch { return json(res, 400, { error: "bad request" }); }
  const account = ACCOUNTS[(req.headers.authorization ?? "").replace(/^Bearer\s+/i, "")];
  const p = url.pathname;

  if (p === "/") {
    res.writeHead(200, { "content-type": "text/html", "set-cookie": "session=demo; Path=/" });
    return res.end('<!doctype html><title>demo app</title><h1>Demo vulnerable app</h1><nav><a href="/api/projects/proj_a_1">project</a> <a href="/api/invoices/inv_b_1">invoice</a></nav><script type="module" src="/app.js"></script><script type="module" src="/auth.js"></script><script type="module" src="/supabase.js"></script><script type="module" src="/http-client.js"></script>');
  }
  // The built client bundle, served like any static host would (maps included, on purpose).
  const asset = p.match(/^\/([\w.-]+\.(?:js|map))$/);
  if (asset) {
    const file = new URL(`./dist/${asset[1]}`, import.meta.url);
    if (!existsSync(file)) return json(res, 404, { error: "not found" });
    res.writeHead(200, { "content-type": asset[1].endsWith(".map") ? "application/json" : "application/javascript" });
    return res.end(readFileSync(file));
  }
  let m = p.match(/^\/api\/projects\/([^/]+)$/);
  if (m) {
    if (!account) return json(res, 401, { error: "sign in" });
    const proj = PROJECTS[decodeURIComponent(m[1])];
    // BUG (on purpose): no ownership check, any account reads any project.
    return proj ? json(res, 200, proj) : json(res, 404, { error: "not found" });
  }
  m = p.match(/^\/api\/renders\/([^/]+)$/);
  if (m) {
    if (!account) return json(res, 401, { error: "sign in" });
    const r = RENDERS[decodeURIComponent(m[1])];
    return r && r.owner === account ? json(res, 200, r) : json(res, 404, { error: "not found" });
  }
  m = p.match(/^\/api\/invoices\/([^/]+)$/);
  if (m) {
    if (!account) return json(res, 401, { error: "sign in" });
    const inv = INVOICES[decodeURIComponent(m[1])];
    // BUG (on purpose): no ownership check, like projects.
    return inv ? json(res, 200, inv) : json(res, 404, { error: "not found" });
  }
  if (p.startsWith("/rest/v1/")) {
    if (req.method !== "GET") return json(res, 405, { message: "demo is read-only" });
    if (req.headers.apikey !== ANON) return json(res, 401, { message: "No API key found in request" });
    if (p === "/rest/v1/") {
      return json(res, 200, {
        swagger: "2.0",
        paths: { "/": {}, "/profiles": {}, "/notes": {}, "/rpc/demo": {} },
        definitions: { profiles: { properties: { id: {}, email: {}, full_name: {}, plan: {} } }, notes: { properties: { id: {}, body: {} } } },
      }, { "content-type": "application/openapi+json" });
    }
    if (p === "/rest/v1/profiles") return json(res, 200, [{ id: 1, email: "founder@demo.test", full_name: "Demo Founder", plan: "pro" }].slice(0, 1));
    if (p === "/rest/v1/notes") return json(res, 200, []); // RLS on: nothing without a session
    return json(res, 404, { message: "relation does not exist" });
  }
  json(res, 404, { error: "not found" });
});

server.listen(PORT, "127.0.0.1", () => process.stdout.write(`demo vulnerable app on http://127.0.0.1:${PORT}\n`));
