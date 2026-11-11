import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request, type Server } from "node:http";
import { connect, type AddressInfo } from "node:net";
import { startEgressProxy, type EgressProxy, type ProxyEvent } from "./egress-proxy.js";
import { Scope } from "./scope.js";

// Every test talks to local servers only. Hosts that are not ours
// (evil.example.com, example.com) are refused before any DNS lookup.

async function upstream(handler: Parameters<typeof createServer>[1]): Promise<{ server: Server; port: number; hits: string[] }> {
  const hits: string[] = [];
  const server = createServer((q, s) => { hits.push(`${q.method} ${q.url}`); handler!(q, s); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, port: (server.address() as AddressInfo).port, hits };
}
const close = (s: Server) => new Promise<void>((r) => s.close(() => r()));

/** Send one request through the proxy, absolute-form. */
function viaProxy(p: EgressProxy, method: string, url: string, auth = true): Promise<{ status: number; body: string; headers: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1", port: p.port, method, path: url,
      headers: auth ? { "proxy-authorization": "Basic " + Buffer.from(`crenel:${p.token}`).toString("base64") } : {},
    }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body, headers: res.headers }));
    });
    req.on("error", reject);
    req.end(method === "POST" ? "x=1" : undefined);
  });
}

/** Open a CONNECT tunnel and return the proxy's status line. */
function connectVia(p: EgressProxy, target: string): Promise<{ line: string; socket: import("node:net").Socket }> {
  return new Promise((resolve, reject) => {
    const s = connect(p.port, "127.0.0.1", () => {
      s.write(`CONNECT ${target} HTTP/1.1\r\nhost: ${target}\r\nproxy-authorization: Basic ${Buffer.from(`crenel:${p.token}`).toString("base64")}\r\n\r\n`);
    });
    let buf = "";
    s.on("data", (c) => {
      buf += c.toString();
      if (buf.includes("\r\n\r\n")) { s.removeAllListeners("data"); resolve({ line: buf.split("\r\n")[0]!, socket: s }); }
    });
    s.on("error", reject);
  });
}

function setup(scopeCfg: ConstructorParameters<typeof Scope>[0], extra: Partial<Parameters<typeof startEgressProxy>[0]> = {}) {
  const events: ProxyEvent[] = [];
  const net: unknown[] = [];
  const scope = new Scope({ ...scopeCfg, onRequest: (e) => net.push(e) });
  return { events, net, start: () => startEgressProxy({ scope, ratePerSec: 1000, onEvent: (e) => events.push(e), ...extra }) };
}

test("a declared host is forwarded, pinned to the checked address, and journalled", async () => {
  const up = await upstream((_q, s) => { s.writeHead(200, { "content-type": "text/plain" }); s.end("hello"); });
  const { events, net, start } = setup({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
  const p = await start();
  try {
    const r = await viaProxy(p, "GET", `http://127.0.0.1:${up.port}/x?y=1`);
    assert.equal(r.status, 200);
    assert.equal(r.body, "hello");
    assert.deepEqual(up.hits, ["GET /x?y=1"]);
    await new Promise((r) => setTimeout(r, 20));
    const ev = events.find((e) => e.status === 200)!;
    assert.equal(ev.ip, "127.0.0.1");
    assert.equal(ev.bytes, 5);
    assert.ok(net.length >= 1, "the scope observer (run journal) sees it too");
  } finally { await p.close(); await close(up.server); }
});

test("headers named in Connection are hop-by-hop: dropped both ways (RFC 9110 §7.6.1)", async () => {
  let got: Record<string, unknown> = {};
  const up = await upstream((q, s) => { got = q.headers; s.writeHead(200, { connection: "x-up-hop", "x-up-hop": "1", "x-up-kept": "1" }); s.end("ok"); });
  const { start } = setup({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
  const p = await start();
  try {
    const r = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port: p.port, method: "GET", path: `http://127.0.0.1:${up.port}/`, headers: {
        "proxy-authorization": "Basic " + Buffer.from(`crenel:${p.token}`).toString("base64"), connection: "X-Hop, keep-alive", "x-hop": "secret", "x-kept": "1",
      } }, (res) => { res.resume(); res.on("end", () => resolve(res.headers)); });
      req.on("error", reject); req.end();
    });
    assert.equal(got["x-hop"], undefined, "a header the client named in Connection reaches the target");
    assert.equal(got["x-kept"], "1");
    assert.equal(r["x-up-hop"], undefined, "a header the target named in Connection reaches the tool");
    assert.equal(r["x-up-kept"], "1");
  } finally { await p.close(); await close(up.server); }
});

test("an undeclared host is refused before any DNS lookup", async () => {
  let resolved = 0;
  const { events, start } = setup({ allowedHosts: ["127.0.0.1"], allowPrivate: true }, { resolve: async () => { resolved++; return ["93.184.215.14"]; } });
  const p = await start();
  try {
    const r = await viaProxy(p, "GET", "http://example.com/");
    assert.equal(r.status, 403);
    assert.match(r.body, /not in allowedHosts/);
    assert.equal(resolved, 0);
    assert.match(events[0]!.refused ?? "", /example\.com is not in allowedHosts/);
  } finally { await p.close(); }
});

test("a declared host that resolves to a private or metadata address is refused", async () => {
  const { events, start } = setup({ allowedHosts: ["staging.example.test", "169.254.169.254"] }, { resolve: async () => ["10.0.0.5"] });
  const p = await start();
  try {
    const r = await viaProxy(p, "GET", "http://staging.example.test/");
    assert.equal(r.status, 403);
    assert.match(r.body, /private address \(10\.0\.0\.5\)/);
    const m = await viaProxy(p, "GET", "http://169.254.169.254/latest/meta-data/");
    assert.equal(m.status, 403, "metadata IP literal refused even when declared, allowPrivate is off");
    assert.equal(events.filter((e) => e.refused).length, 2);
  } finally { await p.close(); }
});

test("one private address among several answers is enough to refuse (rebinding)", async () => {
  const { start } = setup({ allowedHosts: ["mixed.example.test"] }, { resolve: async () => ["8.8.8.8", "127.0.0.1"] });
  const p = await start();
  try {
    assert.equal((await viaProxy(p, "GET", "http://mixed.example.test/")).status, 403);
  } finally { await p.close(); }
});

test("a redirect toward an undeclared host is flagged, and following it is refused", async () => {
  const up = await upstream((_q, s) => { s.writeHead(302, { location: "http://evil.example.com/steal" }); s.end(); });
  const { events, start } = setup({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
  const p = await start();
  try {
    const first = await viaProxy(p, "GET", `http://127.0.0.1:${up.port}/`);
    assert.equal(first.status, 302);
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(events.find((e) => e.status === 302)?.offScopeRedirect, "http://evil.example.com/steal");
    // The tool follows the Location with a new request: checked from scratch.
    const second = await viaProxy(p, "GET", String(first.headers.location));
    assert.equal(second.status, 403);
    assert.match(events.at(-1)!.refused ?? "", /evil\.example\.com is not in allowedHosts/);
  } finally { await p.close(); await close(up.server); }
});

test("a non read-only method is refused on plain HTTP and never reaches the target", async () => {
  const up = await upstream((_q, s) => { s.writeHead(200); s.end("ok"); });
  const { events, start } = setup({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
  const p = await start();
  try {
    for (const m of ["POST", "PUT", "DELETE", "PATCH"]) {
      const r = await viaProxy(p, m, `http://127.0.0.1:${up.port}/api/projects/1`);
      assert.equal(r.status, 405, m);
    }
    assert.deepEqual(up.hits, [], "nothing reached the target");
    assert.equal(events.filter((e) => /only GET, HEAD and OPTIONS/.test(e.refused ?? "")).length, 4);
    assert.equal((await viaProxy(p, "HEAD", `http://127.0.0.1:${up.port}/`)).status, 200);
  } finally { await p.close(); await close(up.server); }
});

test("CONNECT is refused on a port other than 443/80, and to an undeclared host", async () => {
  const { events, start } = setup({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
  const p = await start();
  try {
    const a = await connectVia(p, "127.0.0.1:8443");
    assert.match(a.line, /^HTTP\/1\.1 403/);
    a.socket.destroy();
    const b = await connectVia(p, "example.com:443");
    assert.match(b.line, /^HTTP\/1\.1 403/);
    b.socket.destroy();
    assert.match(events[0]!.refused ?? "", /port 8443: only 443 and 80/);
    assert.match(events[1]!.refused ?? "", /example\.com is not in allowedHosts/);
  } finally { await p.close(); }
});

test("CONNECT to a declared host on an allowed port is tunnelled (bytes only, no method visible)", async () => {
  const up = await upstream((q, s) => { s.writeHead(200); s.end(`seen ${q.method}`); });
  const { events, start } = setup({ allowedHosts: ["127.0.0.1"], allowPrivate: true }, { connectPorts: [up.port] });
  const p = await start();
  try {
    const t = await connectVia(p, `127.0.0.1:${up.port}`);
    assert.match(t.line, /^HTTP\/1\.1 200/);
    // Inside the tunnel the proxy cannot see (or filter) the method: a POST goes through.
    const reply = await new Promise<string>((r) => {
      let b = "";
      t.socket.on("data", (c) => (b += c));
      t.socket.on("close", () => r(b));
      t.socket.write("POST / HTTP/1.1\r\nhost: x\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
    });
    assert.match(reply, /seen POST/);
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(events.find((e) => e.via === "connect")?.status, 200);
  } finally { await p.close(); await close(up.server); }
});

test("without the per-run credential the proxy answers 407", async () => {
  const { events, start } = setup({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
  const p = await start();
  try {
    assert.equal((await viaProxy(p, "GET", "http://127.0.0.1:1/", false)).status, 407);
    assert.match(events[0]!.refused ?? "", /credential/);
  } finally { await p.close(); }
});

test("the response is capped and the request budget is enforced", async () => {
  const up = await upstream((_q, s) => { s.writeHead(200); s.end("x".repeat(10_000)); });
  const { start } = setup({ allowedHosts: ["127.0.0.1"], allowPrivate: true }, { maxResponseBytes: 1000, maxRequests: 2 });
  const p = await start();
  try {
    const r = await viaProxy(p, "GET", `http://127.0.0.1:${up.port}/`);
    assert.ok(r.body.length <= 1000, `capped (${r.body.length})`);
    await viaProxy(p, "GET", `http://127.0.0.1:${up.port}/`);
    const third = await viaProxy(p, "GET", `http://127.0.0.1:${up.port}/`);
    assert.equal(third.status, 403);
    assert.match(third.body, /budget/);
  } finally { await p.close(); await close(up.server); }
});

test("the kill switch refuses everything after abort", async () => {
  const ac = new AbortController();
  const up = await upstream((_q, s) => { s.writeHead(200); s.end("ok"); });
  const { start } = setup({ allowedHosts: ["127.0.0.1"], allowPrivate: true, signal: ac.signal });
  const p = await start();
  try {
    ac.abort();
    const r = await viaProxy(p, "GET", `http://127.0.0.1:${up.port}/`);
    assert.equal(r.status, 403);
    assert.deepEqual(up.hits, []);
  } finally { await p.close(); await close(up.server); }
});
