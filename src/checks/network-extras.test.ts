import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { nextMiddleware } from "./next-middleware.js";
import { makeSubdomainTakeover } from "./subdomain-takeover.js";
import { makeEmailDns } from "./email-dns.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

const ctx = (over: Partial<CheckContext>): CheckContext => ({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", options: {}, log: () => {}, ...over });

test("next-middleware: /dashboard redirects without the header and is served with it", async () => {
  const srv = createServer((req, res) => {
    if (req.url === "/dashboard") {
      if (req.headers["x-middleware-subrequest"]) { res.writeHead(200); return res.end("<h1>Billing for every customer</h1>"); }
      res.writeHead(307, { location: "/login" }); return res.end();
    }
    if (req.url === "/admin") { res.writeHead(403); return res.end("no"); } // patched route: header changes nothing
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const found = await nextMiddleware.run(ctx({ stagingUrl: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` }));
    assert.deepEqual(found.map((f) => f.id), ["next-middleware:/dashboard"]);
    assert.equal(found[0]!.severity, "critical");
  } finally { srv.close(); }
});

test("subdomain-takeover: a CNAME to Heroku answering 'No such app' is proven; a live app or no CNAME is not", async () => {
  const cnames: Record<string, string[]> = { "old.acme.com": ["acme-old.herokuapp.com"], "app.acme.com": ["acme.herokuapp.com"] };
  const bodies: Record<string, string> = { "https://old.acme.com/": "<title>No such app</title>", "https://app.acme.com/": "<h1>Acme</h1>" };
  const check = makeSubdomainTakeover(async (h) => { if (!cnames[h]) throw new Error("ENODATA"); return cnames[h]!; }, async (u) => ({ status: 404, body: bodies[u] ?? "" }));
  const found = await check.run({ scope: new Scope({ allowedHosts: ["old.acme.com", "app.acme.com", "www.acme.com", "10.0.0.1"] }), projectDir: ".", options: {}, log: () => {} });
  assert.deepEqual(found.map((f) => f.id), ["subdomain-takeover:old.acme.com"]);
  assert.match(found[0]!.title, /Heroku/);
});

test("email-dns: no DMARC and an open SPF are reported; a strict setup is clean", async () => {
  const records: Record<string, string[][]> = {
    "acme.com": [["v=spf1 include:_spf.google.com +all"]],
    "strict.com": [["v=spf1 include:_spf.google.com -all"]],
    "_dmarc.strict.com": [["v=DMARC1; p=reject"]],
  };
  const check = makeEmailDns(async (n) => { if (!records[n]) throw new Error("ENODATA"); return records[n]!; });
  const a = await check.run(ctx({ stagingUrl: "https://app.acme.com/" }));
  assert.deepEqual(a.map((f) => f.id.split(":")[1]).sort(), ["no-dmarc", "spf-open"]);
  assert.equal(a.find((f) => f.id.includes("spf-open"))!.severity, "high");
  const b = await check.run(ctx({ stagingUrl: "https://staging.strict.com/" }));
  assert.equal(b.length, 0);
  assert.equal((await check.run(ctx({ stagingUrl: "http://127.0.0.1:3000/" }))).length, 0, "no mail domain for an IP");
});
