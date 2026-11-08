import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { metricsExposed, isPrometheus } from "./metrics-exposed.js";
import { Scope } from "../core/scope.js";

test("isPrometheus: HELP/TYPE is detected, HTML is not", () => {
  assert.ok(isPrometheus("# HELP http_requests_total Total\n# TYPE http_requests_total counter\nhttp_requests_total 5"));
  assert.ok(!isPrometheus("<!DOCTYPE html><html>..."));
  assert.ok(!isPrometheus('{"json":true}'));
  assert.ok(isPrometheus("a_total 1\nb_total 2\nc_total 3\nd_total 4\ne_total 5\nf_total 6"));
});

test("an open /metrics is proven; an SPA is not", async () => {
  const srv = createServer((req, res) => {
    if (req.url === "/metrics") { res.writeHead(200, { "content-type": "text/plain" }); return res.end("# HELP app_up 1\n# TYPE app_up gauge\napp_up 1\n"); }
    res.writeHead(200, { "content-type": "text/html" }); res.end("<!DOCTYPE html><html></html>");
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const found = await metricsExposed.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} });
    assert.equal(found.length, 1);
    assert.equal(found[0]!.id, "metrics-exposed:/metrics");
  } finally { srv.close(); }
});
