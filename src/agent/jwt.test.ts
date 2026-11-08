import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, createPublicKey } from "node:crypto";
import { forgeNoneToken, forgeNoneVariants, forgeHs256, jwkToPems, jwtForgeOracle, corruptSig, headerOf, payloadOf, isRsaAlg, isHmacAlg, WEAK_SECRETS } from "./jwt.js";

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const mkToken = (alg: string, payload: object, sig = "sig") => `${b64({ alg, typ: "JWT" })}.${b64(payload)}.${sig}`;

test("forgeNoneToken / variants: payload kept, override applied, alg set", () => {
  const t = mkToken("RS256", { sub: "a", role: "user" });
  const none = forgeNoneToken(t, { role: "admin" })!;
  assert.equal(headerOf(none)!.alg, "none");
  assert.equal(payloadOf(none)!.role, "admin");
  assert.equal(payloadOf(none)!.sub, "a");
  assert.ok(none.endsWith("."));
  assert.deepEqual(forgeNoneVariants(t).map((x) => headerOf(x)!.alg), ["none", "None", "NONE", "nOnE"]);
});

test("forgeHs256 signs with the given secret (verifiable)", () => {
  const t = mkToken("RS256", { sub: "a" });
  const forged = forgeHs256(t, "s3cr3t", { role: "admin" })!;
  const [h, p, s] = forged.split(".");
  assert.equal(createHmac("sha256", "s3cr3t").update(`${h}.${p}`).digest("base64url"), s);
  assert.equal(headerOf(forged)!.alg, "HS256");
  assert.equal(payloadOf(forged)!.role, "admin");
});

test("jwkToPems turns an RSA JWK into usable PEM strings", () => {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  const pems = jwkToPems(jwk as Record<string, unknown>);
  assert.ok(pems.some((p) => p.includes("BEGIN PUBLIC KEY")) || pems.some((p) => p.includes("BEGIN RSA PUBLIC KEY")));
  // a PEM from the JWK must match the key's own export
  const spki = createPublicKey({ key: jwk as never, format: "jwk" }).export({ type: "spki", format: "pem" }).toString();
  assert.ok(pems.includes(spki) || pems.includes(spki.trimEnd()));
});

test("alg helpers", () => {
  assert.ok(isRsaAlg("RS256") && isRsaAlg("PS384") && !isRsaAlg("HS256"));
  assert.ok(isHmacAlg("HS256") && !isHmacAlg("RS256"));
  assert.ok(WEAK_SECRETS.includes("secret"));
});

test("corruptSig flips the signature", () => {
  const t = "a.b.cccca";
  assert.notEqual(corruptSig(t), t);
  assert.equal(corruptSig("a.b.").length >= 4, true);
});

const ok = { status: 200, body: '{"ok":1}' };
const denied = { status: 401, body: "no" };
test("jwtForgeOracle: forged accepted + corrupted rejected -> proven", () => {
  assert.equal(jwtForgeOracle({ forged: ok, control: denied }).verdict, "proven");
});
test("jwtForgeOracle: corrupted also accepted -> lead (signature ignored)", () => {
  assert.equal(jwtForgeOracle({ forged: ok, control: { status: 200, body: '{"ok":1}' } }).verdict, "lead");
});
test("jwtForgeOracle: forged rejected -> denied", () => {
  assert.equal(jwtForgeOracle({ forged: denied, control: denied }).verdict, "denied");
});
