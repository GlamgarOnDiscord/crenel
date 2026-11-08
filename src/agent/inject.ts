// Generic injection oracles for the exploration layer (explore.injection).
//
// These prove an injection the way the authz oracle proves a leak: by a
// deterministic differential, a reflection or a computation the server performed
// — never by a signature for a particular target. The exploration model may
// point at a candidate parameter; the validator generates its OWN payloads from
// a fresh nonce and these oracles decide. A guess, an error page or the model's
// confidence never counts.
//
// Three classes, each a pure function so it is tested without a network:
//   - reflected XSS: a nonce wrapped in an HTML-breaking payload comes back
//     verbatim and UNESCAPED in the body (escaped reflection is only a lead).
//   - SQL injection: boolean-based (a TRUE condition matches the baseline while
//     a FALSE one differs materially) or error-based (a database error surfaces).
//   - template/command injection: a unique arithmetic the server computed
//     (nonce + 7*7 -> nonce + "49") appears, so it cannot be a coincidence.

import { createHash } from "node:crypto";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export type InjVerdict = { verdict: "proven" | "lead" | "denied"; kind: string; reason: string };

/** A short, unique, URL-safe token to tie a probe to its response. */
export function nonce(seed = ""): string {
  return "cr" + sha(seed + Date.now() + Math.random()).slice(0, 10);
}

/** Common SQL error fragments across engines — evidence of error-based SQLi. */
const SQL_ERRORS = [
  "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
  "unclosed quotation mark", "quoted string not properly terminated",
  "pg_query", "postgresql", "psql:", "sqlite3.operationalerror", "sqlite error",
  "ora-0", "odbc", "sqlstate", "syntax error at or near", "unterminated quoted string",
];

/* ---------------- reflected XSS ---------------- */
// payload the validator should send: `<svg/onload=1>${token}` (angle brackets matter).
export function xssOracle(input: { token: string; body: string; status: number }): InjVerdict {
  const { token, body } = input;
  if (!body.includes(token)) return { verdict: "denied", kind: "xss", reason: "the marker is not reflected at all" };
  // Raw, HTML-breaking reflection: the tag characters survive unescaped next to the token.
  const rawForms = [`<svg/onload=1>${token}`, `<svg/onload=1>`, `"><svg`, `<script>${token}`];
  if (rawForms.some((f) => body.includes(f))) {
    return { verdict: "proven", kind: "xss", reason: "the injected markup is reflected unescaped (HTML context)" };
  }
  // Reflected but the angle brackets were encoded -> not exploitable as-is.
  if (body.includes(`&lt;svg`) || body.includes(`&#60;svg`) || body.includes(`\\u003csvg`)) {
    return { verdict: "lead", kind: "xss", reason: "the marker is reflected but the markup is HTML-escaped" };
  }
  return { verdict: "lead", kind: "xss", reason: "the marker is reflected; escaping context unclear, review by hand" };
}

/* ---------------- SQL injection ---------------- */
// baseline: the param's normal value; truthy: value + "' OR '1'='1"; falsy: value + "' AND '1'='2".
export function sqliOracle(input: {
  baseline: { status: number; body: string };
  truthy: { status: number; body: string };
  falsy: { status: number; body: string };
}): InjVerdict {
  const { baseline, truthy, falsy } = input;
  const errored = [truthy, falsy].find((r) => SQL_ERRORS.some((e) => r.body.toLowerCase().includes(e)));
  if (errored) return { verdict: "proven", kind: "sqli-error", reason: "a database error surfaced when the quote was injected" };
  const same = (a: { status: number; body: string }, b: { status: number; body: string }) =>
    a.status === b.status && (a.body === b.body || sha(a.body) === sha(b.body));
  // Boolean-based: TRUE behaves like the baseline, FALSE diverges from both.
  const truthyLikeBase = same(truthy, baseline);
  const falsyDiffers = !same(falsy, baseline) && !same(falsy, truthy);
  if (truthyLikeBase && falsyDiffers) {
    return { verdict: "proven", kind: "sqli-boolean", reason: "TRUE condition matches the baseline while FALSE diverges (boolean-based)" };
  }
  if (!same(truthy, falsy)) {
    return { verdict: "lead", kind: "sqli", reason: "TRUE and FALSE responses differ but not cleanly against the baseline: review by hand" };
  }
  return { verdict: "denied", kind: "sqli", reason: "no differential between TRUE and FALSE injections" };
}

/* ---------------- NoSQL injection ---------------- */
// Mongo/document stores: operator injection ($ne, $gt, $in) through bracket query
// keys or a JSON body turns a filter into always-true / always-false. The proof is
// the same boolean differential as SQLi (an always-true operator behaves like the
// baseline while an always-false one diverges), or a document-store parse error.
// Generic operator technique, no target signature.
const NOSQL_ERRORS = [
  "mongoerror", "bson", "unknown operator", "$where", "casterror",
  "failed to parse", "e11000", "unterminated object", "unexpected token in json",
];
export function nosqlOracle(input: {
  baseline: { status: number; body: string };
  truthy: { status: number; body: string };
  falsy: { status: number; body: string };
}): InjVerdict {
  const { baseline, truthy, falsy } = input;
  const errored = [truthy, falsy].find((r) => NOSQL_ERRORS.some((e) => r.body.toLowerCase().includes(e)));
  if (errored) return { verdict: "proven", kind: "nosqli-error", reason: "a document-store parse error surfaced when an operator was injected" };
  const same = (a: { status: number; body: string }, b: { status: number; body: string }) =>
    a.status === b.status && (a.body === b.body || sha(a.body) === sha(b.body));
  const truthyLikeBase = same(truthy, baseline);
  const falsyDiffers = !same(falsy, baseline) && !same(falsy, truthy);
  if (truthyLikeBase && falsyDiffers) {
    return { verdict: "proven", kind: "nosqli-boolean", reason: "an always-true operator ($ne) matches the baseline while an always-false one ($eq) diverges (boolean-based)" };
  }
  // Auth/filter bypass: the always-true operator SUCCEEDS where the literal value
  // and the always-false operator are both denied -> the operator was interpreted.
  const ok = (r: { status: number; body: string }) => r.status >= 200 && r.status < 300;
  if (ok(truthy) && !ok(baseline) && !ok(falsy) && !same(truthy, falsy)) {
    return { verdict: "proven", kind: "nosqli-bypass", reason: "an always-true operator ($ne) is accepted where the literal value and an always-false operator ($eq) are both denied (auth/filter bypass)" };
  }
  if (!same(truthy, falsy)) {
    return { verdict: "lead", kind: "nosqli", reason: "operator-injected responses differ but not cleanly against the baseline: review by hand" };
  }
  return { verdict: "denied", kind: "nosqli", reason: "no differential between always-true and always-false operators" };
}

/* ---------------- template / command injection ---------------- */
// payload: `${token}` wraps a computation, e.g. send `A${token}B` where the raw
// marker is `<nonce>` and the computed marker is `<nonce>` with 7*7 replaced by 49.
// The validator sends a value like `${nonce}-${49-probe}` using engine-specific
// forms; this oracle just checks the computed result appears tied to the nonce.
export function templateOracle(input: { token: string; product: string; body: string }): InjVerdict {
  const { token, product, body } = input;
  // The server must have evaluated the expression: token immediately followed by the product (49).
  if (body.includes(token + product)) {
    return { verdict: "proven", kind: "template-injection", reason: `the server evaluated the expression (${token}${product} in the response)` };
  }
  if (body.includes(product) && body.includes(token)) {
    return { verdict: "lead", kind: "template-injection", reason: "both the nonce and the computed value appear but not adjacent: review by hand" };
  }
  if (body.includes(token)) return { verdict: "lead", kind: "template-injection", reason: "the nonce is reflected but the expression was not evaluated" };
  return { verdict: "denied", kind: "template-injection", reason: "no evaluation of the injected expression" };
}
