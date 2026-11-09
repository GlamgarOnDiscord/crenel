import { test } from "node:test";
import assert from "node:assert/strict";
import { redirectOracle, redirectHost } from "./redirect.js";

const REQ = "https://app.example/login?next=x";
const S1 = "crenel-redirect-aaa.invalid", S2 = "crenel-redirect-bbb.invalid";
const loc = (host: string, status = 302): { status: number; location: string; body: string } => ({ status, location: `https://${host}/landing`, body: "" });

test("redirect: both sentinels reflected into a 302 Location -> proven medium", () => {
  const v = redirectOracle({ reqUrl: REQ, s1: S1, r1: loc(S1), s2: S2, r2: loc(S2) });
  assert.equal(v.verdict, "proven");
  assert.equal(v.ceiling, "medium");
});

test("redirect: protocol-relative Location is resolved to the sentinel host -> proven", () => {
  const v = redirectOracle({
    reqUrl: REQ,
    s1: S1, r1: { status: 301, location: `//${S1}/x`, body: "" },
    s2: S2, r2: { status: 301, location: `//${S2}/x`, body: "" },
  });
  assert.equal(v.verdict, "proven");
});

test("redirect: a meta-refresh to both sentinels on a 200 page -> proven", () => {
  const meta = (h: string) => ({ status: 200, location: null, body: `<meta http-equiv="refresh" content="0;url=https://${h}/go">` });
  const v = redirectOracle({ reqUrl: REQ, s1: S1, r1: meta(S1), s2: S2, r2: meta(S2) });
  assert.equal(v.verdict, "proven");
});

test("redirect: a route that always redirects to one fixed host -> denied (no reflection)", () => {
  const fixed = loc("accounts.app.example");
  const v = redirectOracle({ reqUrl: REQ, s1: S1, r1: fixed, s2: S2, r2: fixed });
  assert.equal(v.verdict, "denied");
});

test("redirect: a partial allowlist that reflects only one guess -> denied", () => {
  const v = redirectOracle({ reqUrl: REQ, s1: S1, r1: loc(S1), s2: S2, r2: loc("trusted.partner.example") });
  assert.equal(v.verdict, "lead");
});

test("redirect: a relative in-site Location (no off-site redirect) -> denied", () => {
  const rel = { status: 302, location: "/dashboard", body: "" };
  const v = redirectOracle({ reqUrl: REQ, s1: S1, r1: rel, s2: S2, r2: rel });
  assert.equal(v.verdict, "denied");
});

test("redirect: a 200 with no Location and no meta refresh -> denied", () => {
  const none = { status: 200, location: null, body: "<html>ok</html>" };
  const v = redirectOracle({ reqUrl: REQ, s1: S1, r1: none, s2: S2, r2: none });
  assert.equal(v.verdict, "denied");
});

test("redirect: a Location on a 3xx is honoured, a Location header on a 200 is ignored", () => {
  // Some servers echo a Location header on a 200 without redirecting: not a redirect.
  assert.equal(redirectHost({ status: 200, location: `https://${S1}/x`, body: "" }, REQ), null);
  assert.equal(redirectHost({ status: 302, location: `https://${S1}/x`, body: "" }, REQ), S1);
});
