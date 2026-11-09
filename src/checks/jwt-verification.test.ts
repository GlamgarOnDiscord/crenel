import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPairSync, createSign, createHmac } from "node:crypto";
import { jwtVerification } from "./jwt-verification.js";
import { Scope } from "../core/scope.js";

test("jwt-verification proves RS->HS confusion deterministically from a declared endpoint", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const si = `${b64({ alg: "RS256", typ: "JWT" })}.${b64({ sub: "a", role: "user" })}`;
  const rs = `${si}.${createSign("RSA-SHA256").update(si).sign(privateKey, "base64url")}`;
  const srv = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    const json = (s: number, b: unknown) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
    if (u.pathname === "/.well-known/jwks.json") return json(200, { keys: [jwk] });
    if (u.pathname !== "/me") return json(404, {});
    const tok = (req.headers.authorization || "").replace(/^Bearer /, "");
    const [h, p, s] = tok.split(".");
    if (!h || !p || s === undefined) return json(401, {});
    let alg = ""; try { alg = JSON.parse(Buffer.from(h, "base64url").toString()).alg; } catch { return json(401, {}); }
    const ok = alg === "HS256" && s === createHmac("sha256", pubPem).update(`${h}.${p}`).digest("base64url");
    return ok ? json(200, { me: "ok" }) : json(401, {});
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const found = await jwtVerification.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, log: () => {},
      options: { "authz-matrix": { accounts: { a: { token: rs } } }, "jwt-verification": { endpoints: ["/me"], as: "a" } } });
    assert.ok(found.find((f) => f.id.startsWith("jwt-verification:")), "confusion proven");
    assert.equal(found[0]!.severity, "critical");
  } finally { srv.close(); }
});

test("jwt-verification is opt-in: no endpoints -> nothing", async () => {
  const found = await jwtVerification.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: "http://127.0.0.1:1", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});
