import { test } from "node:test";
import assert from "node:assert/strict";
import { isGraphqlQueryOnly, isPrivateIp, readOnlyPost, safeFetch } from "./net.js";
import { Scope } from "./scope.js";

test("private and loopback addresses are refused", () => {
  for (const ip of ["127.0.0.1", "10.0.0.5", "192.168.1.10", "172.16.4.4", "172.31.255.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1"]) {
    assert.equal(isPrivateIp(ip), true, `${ip} should be private`);
  }
});

// The exact cloud-metadata endpoints the 2026 agent SSRF CVEs target
// (PraisonAI, Pydantic AI, AgentScope). Pinned so the guard can never regress.
test("cloud metadata endpoints are refused, in every form", () => {
  for (const ip of [
    "169.254.169.254", // AWS/GCP IMDS (IPv4 link-local)
    "fd00:ec2::254", // AWS IMDS over IPv6 (unique-local)
    "100.100.100.200", // Alibaba metadata (CGNAT range)
    "::ffff:169.254.169.254", // IPv4-mapped link-local, dotted form
    "::ffff:a9fe:a9fe", // same address, hex-compressed v4-mapped form
    "::ffff:7f00:1", // 127.0.0.1 in hex-compressed v4-mapped form
  ]) {
    assert.equal(isPrivateIp(ip), true, `${ip} must be refused`);
  }
});

test("special IPv6 and reserved IPv4 ranges are refused", () => {
  for (const ip of [
    "2002::1", "64:ff9b::808:808", "fec0::1", "febf::1", "ff02::1", // 6to4, NAT64, site-local, link-local, multicast
    "::7f00:1", "::192.168.1.1", // v4-compatible
    "192.0.0.1", "198.18.5.5", "192.88.99.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
  ]) {
    assert.equal(isPrivateIp(ip), true, `${ip} must be refused`);
  }
});

test("public addresses are allowed", () => {
  for (const ip of ["1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "11.0.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]) {
    assert.equal(isPrivateIp(ip), false, `${ip} should be public`);
  }
});

test("safeFetch returns the body for an allowed host", async () => {
  const http = await import("node:http");
  const server = http.createServer((_q, s) => { s.writeHead(200); s.end("hello"); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    const res = await safeFetch(`http://127.0.0.1:${port}/`, scope);
    assert.equal(res.status, 200);
    assert.equal(res.body, "hello");
  } finally { await new Promise<void>((r) => server.close(() => r())); }
});

test("safeFetch refuses a redirect that leaves the allowlist", async () => {
  const http = await import("node:http");
  const server = http.createServer((_q, s) => { s.writeHead(302, { location: "http://evil.example.com/" }); s.end(); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    await assert.rejects(() => safeFetch(`http://127.0.0.1:${port}/`, scope), /not in allowedHosts|Refused/);
  } finally { await new Promise<void>((r) => server.close(() => r())); }
});

test("safeFetch caps the body", async () => {
  const http = await import("node:http");
  const big = "x".repeat(3 * 1024 * 1024); // > 2 MB cap
  const server = http.createServer((_q, s) => { s.writeHead(200); s.end(big); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    const res = await safeFetch(`http://127.0.0.1:${port}/`, scope);
    assert.ok(res.truncated, "oversized body is truncated");
    assert.ok(res.body.length <= 2 * 1024 * 1024);
  } finally { await new Promise<void>((r) => server.close(() => r())); }
});

test("isGraphqlQueryOnly: queries pass, mutations and subscriptions never do", () => {
  assert.ok(isGraphqlQueryOnly("query{__schema{types{name}}}"));
  assert.ok(isGraphqlQueryOnly("{ me { id } }"));
  assert.ok(isGraphqlQueryOnly('query Q { search(q: "mutation") { id } }'), "the word inside a string is fine");
  assert.ok(!isGraphqlQueryOnly("mutation { deleteUser(id: 1) }"));
  assert.ok(!isGraphqlQueryOnly("query A { me { id } } mutation B { x }"), "a second operation counts");
  assert.ok(!isGraphqlQueryOnly("subscription { ticks }"));
  assert.ok(!isGraphqlQueryOnly("# comment\nmutation { x }"));
  assert.ok(!isGraphqlQueryOnly("fragment F on User { id } query { me { ...F } }"), "anything not starting as a query is refused");
});

test("readOnlyPost: only GraphQL queries, MCP list calls and OSV lookups", () => {
  const u = "https://app.example.com/graphql";
  assert.equal(readOnlyPost(u, JSON.stringify({ query: "{ me { id } }" })), "graphql-query");
  assert.equal(readOnlyPost(u, JSON.stringify({ query: "mutation { x }" })), null);
  assert.equal(readOnlyPost(u, JSON.stringify([{ query: "{ a }" }])), null, "batches are refused");
  assert.equal(readOnlyPost(u, JSON.stringify({ query: "{ a }", extensions: {} })), null, "unknown keys are refused");
  assert.equal(readOnlyPost(u, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })), "mcp-list");
  assert.equal(readOnlyPost(u, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "x" } })), null);
  assert.equal(readOnlyPost("https://api.osv.dev/v1/querybatch", "{}"), "osv-lookup");
  assert.equal(readOnlyPost(u, "a=b"), null);
  assert.equal(readOnlyPost(u, undefined), null);
});

test("safeFetch refuses writes unless the body is a read or active testing is on", async () => {
  const http = await import("node:http");
  const seen: string[] = [];
  const server = http.createServer((q, s) => { seen.push(q.method!); s.writeHead(200); s.end("{}"); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  const url = `http://127.0.0.1:${port}/graphql`;
  try {
    const ro = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    await assert.rejects(safeFetch(url, ro, { method: "DELETE" }), /not a read/);
    await assert.rejects(safeFetch(url, ro, { method: "POST", body: JSON.stringify({ query: "mutation { x }" }) }), /not a read/);
    assert.equal((await safeFetch(url, ro, { method: "POST", body: JSON.stringify({ query: "{ me { id } }" }) })).status, 200);
    const active = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true });
    assert.equal((await safeFetch(url, active, { method: "DELETE" })).status, 200);
    assert.deepEqual(seen, ["POST", "DELETE"]);
  } finally { server.close(); }
});
