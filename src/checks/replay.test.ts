import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { replay } from "./replay.js";
import { Scope } from "../core/scope.js";
import type { CheckContext, Finding } from "../core/types.js";

function run(server: Server, options: Record<string, unknown>): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const port = (server.address() as AddressInfo).port;
      const ctx: CheckContext = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }),
        projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {},
      };
      try { resolve(await replay.run(ctx)); } catch (e) { reject(e); } finally { server.close(); }
    });
  });
}

const target = {
  "replay": { enabled: true, targets: [{ name: "coupon", path: "/coupon/apply", body: { code: "SAVE10" }, tokenField: "code", accepted: { statuses: [200], bodyIncludes: "applied" }, readBack: { path: "/balance", field: "credit" } }] },
};

// A coupon server that mints credit every time the code is sent (replay bug).
function vulnerableServer(): Server {
  let credit = 0;
  return createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/balance") { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ credit })); }
      const code = (() => { try { return JSON.parse(b).code; } catch { return ""; } })();
      if (code !== "SAVE10") { res.writeHead(400); return res.end('{"error":"invalid coupon"}'); }
      credit += 10; // never marks the coupon used
      res.writeHead(200, { "content-type": "application/json" }); res.end('{"status":"applied","credit":' + credit + "}");
    });
  });
}

test("replay: a coupon honored a second time is proven (effect compounds, invalid rejected)", async () => {
  const found = await run(vulnerableServer(), target);
  const proven = found.filter((f) => f.state === "proven");
  assert.equal(proven.length, 1, "the replayed coupon is the one proof");
  assert.match(proven[0]!.title, /accepted twice/);
  assert.equal(proven[0]!.severity, "high");
  assert.match(proven[0]!.proof?.evidence ?? "", /credit.*0.*20|0 -> 20/s);
});

test("replay: a correctly single-use coupon (second use rejected) is NOT proven", async () => {
  let credit = 0; const used = new Set<string>();
  const server = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/balance") { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ credit })); }
      const code = (() => { try { return JSON.parse(b).code; } catch { return ""; } })();
      if (code !== "SAVE10") { res.writeHead(400); return res.end('{"error":"invalid coupon"}'); }
      if (used.has(code)) { res.writeHead(409); return res.end('{"error":"coupon already redeemed"}'); }
      used.add(code); credit += 10;
      res.writeHead(200, { "content-type": "application/json" }); res.end('{"status":"applied","credit":' + credit + "}");
    });
  });
  const found = await run(server, target);
  assert.ok(!found.some((f) => f.state === "proven"), "a single-use coupon is not a replay");
});

test("replay: an accept-all endpoint (invalid token accepted) proves nothing, no false positive", async () => {
  // Returns "applied" to any code, including the control's random invalid one.
  const server = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/balance") { res.writeHead(200, { "content-type": "application/json" }); return res.end('{"credit":0}'); }
      res.writeHead(200, { "content-type": "application/json" }); res.end('{"status":"applied"}');
    });
  });
  const found = await run(server, target);
  assert.ok(!found.some((f) => f.state === "proven"), "accept-all is not a replay proof");
});

test("replay: off unless active testing is enabled (scope gate holds)", async () => {
  const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: false });
  await assert.rejects(
    () => replay.run({ scope, projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: target, log: () => {} }),
    /active/i,
  );
});

test("replay: enabled but with no targets yields no findings (reaches the empty-targets branch)", async () => {
  const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true });
  const found = await replay.run({ scope, projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: { replay: { enabled: true, targets: [] } }, log: () => {} });
  assert.equal(found.length, 0);
});

test("replay: disabled (no enabled flag) yields no findings and sends nothing", async () => {
  const found = await replay.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});
