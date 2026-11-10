import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { defaultCreds } from "./default-creds.js";
import { Scope } from "../core/scope.js";

// A login stand-in: `weak@x` logs in with "admin123" (a known weak password) and
// rejects anything else (so the control holds); `strong@x` rejects every dict
// password; `open@x` accepts ANY password (accept-all → must NOT be flagged).
function loginServer() {
  return createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
      let email = "", password = ""; try { ({ email, password } = JSON.parse(b)); } catch {}
      const ok = () => { res.writeHead(200, { "content-type": "application/json" }); res.end('{"authentication":{"token":"t"}}'); };
      const no = () => { res.writeHead(401); res.end('{"error":"invalid"}'); };
      if (email === "weak@x") return password === "admin123" ? ok() : no();
      if (email === "open@x") return ok(); // accepts anything
      return no(); // strong@x and everyone else
    });
  });
}

async function run(accounts: string[]) {
  const srv = loginServer();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as AddressInfo).port;
  try {
    return await defaultCreds.run({
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }),
      projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`,
      options: { "default-creds": { enabled: true, endpoints: [{ url: "/login", userField: "email", passField: "password", accounts }] } },
      log: () => {},
    });
  } finally { await new Promise<void>((r) => srv.close(() => r())); }
}

test("default-creds: a weak password accepted with a rejecting control is proven", async () => {
  const f = await run(["weak@x"]);
  const p = f.filter((x) => x.state === "proven");
  assert.equal(p.length, 1);
  assert.match(p[0]!.proof!.evidence!, /admin123/);
});
test("default-creds: a strong account is not flagged", async () => {
  assert.equal((await run(["strong@x"])).filter((x) => x.state === "proven").length, 0);
});
test("default-creds: an accept-all endpoint is not flagged (control fails open is avoided)", async () => {
  assert.equal((await run(["open@x"])).filter((x) => x.state === "proven").length, 0);
});
test("default-creds: does nothing unless opted in, and refuses without active mode", async () => {
  const off = await defaultCreds.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }), projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: {}, log: () => {} });
  assert.equal(off.length, 0);
  await assert.rejects(() => defaultCreds.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: false, allowPrivate: true }), projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: { "default-creds": { enabled: true, endpoints: [{ url: "/login" }] } }, log: () => {} }), /active/i);
});
