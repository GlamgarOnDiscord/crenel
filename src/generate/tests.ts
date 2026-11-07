// Turn findings into regression tests. This is the product's thesis made real:
// a finding is not closed when it is noticed, it is closed when a test proves it
// cannot come back. We emit a single framework-agnostic test file (vitest shape)
// with one test per finding, derived deterministically from its check.

import type { Finding } from "../core/types.js";

function esc(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$/g, "\\$");
}

function testFor(f: Finding): string | null {
  const title = esc(`${f.check}: ${f.title}`);
  switch (f.check) {
    case "exposed-secrets": {
      const file = f.location.split(":")[0];
      return [
        `test(${JSON.stringify(title)}, () => {`,
        `  // The secret must not be present in the built output.`,
        `  const src = readFileSync(${JSON.stringify(file)}, "utf8");`,
        `  expect(src).not.toMatch(/sk_(live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY/);`,
        `});`,
      ].join("\n");
    }
    case "dependency-risk": {
      const m = f.title.match(/:\s*([^\s]+@[^\s]+)/);
      if (!m) return null;
      return [
        `test(${JSON.stringify(title)}, () => {`,
        `  const lock = readFileSync("pnpm-lock.yaml", "utf8");`,
        `  expect(lock).not.toContain(${JSON.stringify(m[1])});`,
        `});`,
      ].join("\n");
    }
    case "ci-hardening": {
      const file = f.location.split(":")[0];
      return [
        `test(${JSON.stringify(title)}, () => {`,
        `  const wf = readFileSync(${JSON.stringify(file)}, "utf8");`,
        `  expect(wf).not.toContain("pull_request_target");`,
        `});`,
      ].join("\n");
    }
    case "tls-verification": {
      const file = f.location.split(":")[0];
      return [
        `test(${JSON.stringify(title)}, () => {`,
        `  const src = readFileSync(${JSON.stringify(file)}, "utf8");`,
        `  expect(src).not.toMatch(/rejectUnauthorized\\s*:\\s*false|NODE_TLS_REJECT_UNAUTHORIZED\\s*[=:]\\s*['"]?0|strictSSL\\s*:\\s*false/);`,
        `});`,
      ].join("\n");
    }
    case "jwt-config": {
      const file = f.location.split(":")[0];
      return [
        `test(${JSON.stringify(title)}, () => {`,
        `  const src = readFileSync(${JSON.stringify(file)}, "utf8");`,
        `  expect(src).not.toMatch(/(algorithms?|alg)\\s*:\\s*\\[?[^\\]\\n]*['"]none['"]/i);`,
        `});`,
      ].join("\n");
    }
    case "committed-credentials": {
      // the committed credential file must be gone (and the credential rotated).
      return [
        `test(${JSON.stringify(title)}, () => {`,
        `  expect(existsSync(${JSON.stringify(f.location)})).toBe(false);`,
        `});`,
      ].join("\n");
    }
    case "committed-env": {
      // location is the committed .env path; it must no longer be tracked.
      return [
        `test(${JSON.stringify(title)}, () => {`,
        `  // The committed env file must be gone.`,
        `  expect(existsSync(${JSON.stringify(f.location)})).toBe(false);`,
        `});`,
      ].join("\n");
    }
    case "sourcemaps": {
      const file = f.location.split(":")[0];
      // A shipped .map must not be in the bundle; a sourceMappingURL must be gone.
      if (f.id.startsWith("sourcemaps:file:")) {
        return [
          `test(${JSON.stringify(title)}, () => {`,
          `  expect(existsSync(${JSON.stringify(file)})).toBe(false);`,
          `});`,
        ].join("\n");
      }
      return [
        `test(${JSON.stringify(title)}, () => {`,
        `  const src = readFileSync(${JSON.stringify(file)}, "utf8");`,
        `  expect(src).not.toMatch(/sourceMappingURL=(?!data:)/);`,
        `});`,
      ].join("\n");
    }
    case "public-env": {
      const file = f.location.split(":")[0];
      const m = f.title.match(/:\s*([A-Z0-9_]+)\s*$/); // the var name
      if (!m) return null;
      return [
        `test(${JSON.stringify(title)}, () => {`,
        `  const src = readFileSync(${JSON.stringify(file)}, "utf8");`,
        `  expect(src).not.toContain(${JSON.stringify(m[1])});`,
        `});`,
      ].join("\n");
    }
    case "authz-matrix": {
      // One test per proven object, on that exact object: a fix that only
      // covers new objects (old rows still leaking) fails here. Leads and the
      // offline plan have nothing concrete to assert.
      if (f.state !== "proven") return null;
      let path: string;
      try { const u = new URL(f.location); path = u.pathname + u.search; } catch { return null; }
      const token = /:c(:discovered)?$/.test(f.id) ? "TOKEN_C" : "TOKEN_A";
      return [
        `test(${JSON.stringify(title)}, async () => {`,
        `  // This object belongs to account B: another account, and nobody signed out, must be denied.`,
        `  for (const auth of [{ authorization: \`Bearer \${${token}}\` }, {}]) {`,
        `    const res = await fetch(\`\${BASE_URL}${esc(path)}\`, { headers: auth });`,
        `    expect([401, 403, 404]).toContain(res.status);`,
        `  }`,
        `});`,
      ].join("\n");
    }
    case "live-bundle": {
      if (f.state !== "proven") return null;
      const url = f.location.replace(/:\d+$/, "");
      const isMap = f.id.startsWith("live-bundle:sourcemap:");
      return [
        `test(${JSON.stringify(title)}, async () => {`,
        isMap
          ? `  expect((await fetch(${JSON.stringify(url)})).status).not.toBe(200);`
          : `  const src = await (await fetch(${JSON.stringify(url)})).text();\n  expect(src).not.toMatch(/sk_(live|test)_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|sb_secret_|AIza[0-9A-Za-z_-]{35}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY/);`,
        `});`,
      ].join("\n");
    }
    case "exposed-files": {
      if (f.state !== "proven") return null;
      return [
        `test(${JSON.stringify(title)}, async () => {`,
        `  expect((await fetch(${JSON.stringify(f.location)})).status).not.toBe(200);`,
        `});`,
      ].join("\n");
    }
    case "baas-exposure": {
      // Only a proven read (a table or database root answered without auth)
      // becomes a test; a lead has nothing concrete to assert yet.
      if (f.state !== "proven") return null;
      if (f.id.startsWith("baas-exposure:firebase-rtdb:")) {
        return [
          `test(${JSON.stringify(title)}, async () => {`,
          `  // The Realtime Database root must not be readable without signing in.`,
          `  const res = await fetch(${JSON.stringify(f.location.replace(/\/\.json$/, "") + "/.json?shallow=true")});`,
          `  expect(res.status === 401 || res.status === 403 || (await res.json()) === null).toBe(true);`,
          `});`,
        ].join("\n");
      }
      const m = f.location.match(/^(.*)\/rest\/v1\/([A-Za-z0-9_]+)$/);
      if (!m) return null;
      return [
        `test(${JSON.stringify(`the table ${m[2]} is not readable with the anon key`)}, async () => {`,
        `  // Supabase RLS: the public key alone must never return a row.`,
        `  const key = process.env.SUPABASE_ANON_KEY!;`,
        `  const res = await fetch(${JSON.stringify(`${m[1]}/rest/v1/${m[2]}?select=*&limit=1`)}, {`,
        "    headers: { apikey: key, authorization: `Bearer ${key}` },",
        `  });`,
        `  const rows = res.ok ? await res.json() : [];`,
        `  expect(Array.isArray(rows) ? rows.length : 0).toBe(0);`,
        `});`,
      ].join("\n");
    }
    default:
      return null;
  }
}

/** One regression file covering every finding we know how to assert. */
export function generateRegressionFile(findings: Finding[]): string {
  const needsAuthz = findings.some((f) => f.check === "authz-matrix");
  const bodies = findings.map(testFor).filter((x): x is string => x !== null);
  const header = [
    "// Generated by Crenel. One test per finding, so a fixed issue cannot return.",
    "// Run in CI on every pull request. Fill in the authz env vars if present.",
    "// File paths below are relative to the scanned directory (projectDir). Run",
    "// these tests from that directory, or prefix the paths, so readFileSync",
    "// resolves against the right root.",
    'import { test, expect } from "vitest";',
    'import { readFileSync, existsSync } from "node:fs";',
  ];
  if (needsAuthz) {
    header.push(
      "",
      "const BASE_URL = process.env.STAGING_URL!;",
      "const TOKEN_A = process.env.TEST_TOKEN_A!;",
      "const TOKEN_C = process.env.TEST_TOKEN_C ?? TOKEN_A;",
    );
  }
  return header.join("\n") + "\n\n" + bodies.join("\n\n") + "\n";
}
