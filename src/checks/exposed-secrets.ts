// exposed-secrets: scan a built frontend bundle (or any directory) for secrets
// that should never ship to the browser. This is read-only and deterministic,
// which is exactly the kind of check that research says LLMs should NOT replace:
// a regex on known key shapes has near-zero false positives and no token cost.
//
// The classic SaaS mistake this catches: a server-side key (Stripe secret,
// service-role JWT, private API key) pulled into client code and bundled into
// dist/, where anyone can read it with view-source.

import { readFileSync, statSync } from "node:fs";

import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, extOf, relative } from "../core/walk.js";
import { checkLiveness, verifierHost, type Liveness } from "./key-liveness.js";

export interface SecretPattern {
  id: string;
  title: string;
  regex: RegExp;
  severity: Finding["severity"];
  /** False for test-mode keys that are safe to expose; keeps messaging honest. */
  sensitive?: boolean;
  /**
   * Optional second look at a match, with the surrounding file. Returns false to
   * drop it. Used where the key shape alone is ambiguous (a JWT is only a secret
   * when its decoded role says so; a Google key inside a Firebase web config is
   * public by design and is reported by baas-exposure instead).
   */
  accept?: (match: string, content: string, index: number) => boolean;
}

/**
 * Placeholders that only look like keys: "sk_live_xxxxxxxx", "your_api_key_here",
 * "sk_test_EXAMPLE…", or a body that is one repeated character. Docs, .env
 * templates and tutorials are full of them; reporting them is pure noise.
 */
export function isPlaceholder(match: string): boolean {
  const body = match.replace(/^[A-Za-z]{2,8}[_-](?:live|test|proj|ant)?[_-]?/, "");
  if (/x{4,}|\*{4,}|\.{3,}|<[^>]*>/i.test(body)) return true;
  if (/your|example|placeholder|dummy|changeme|replace|redacted|insert|sample/i.test(body)) return true;
  const top = Math.max(...[...new Set(body)].map((c) => body.split(c).length - 1));
  return body.length >= 8 && top / body.length >= 0.8;
}

/** Decode the payload of a JWT-shaped string, or null. Never verifies the signature. */
export function jwtPayload(token: string): Record<string, unknown> | null {
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    const obj = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return obj && typeof obj === "object" ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** True when a Google API key sits inside a Firebase web config (public by design). */
export function inFirebaseConfig(content: string, index: number): boolean {
  const around = content.slice(Math.max(0, index - 600), index + 600);
  return /\b(authDomain|projectId|storageBucket|messagingSenderId|databaseURL)\b/.test(around) &&
    /firebaseapp\.com|firebaseio\.com|firebasedatabase\.app|appspot\.com|projectId/.test(around);
}

// Patterns are intentionally specific. We match distinctive prefixes rather than
// generic "looks like a token", to keep false positives near zero. Stripe test
// keys (sk_test_/rk_test_) are published by design, so they are a low-severity
// note, not a critical "assume compromised" finding.
export const PATTERNS: SecretPattern[] = [
  { id: "stripe-secret", title: "Stripe secret key (live)", regex: /\bsk_live_[A-Za-z0-9]{16,}/g, severity: "critical", sensitive: true },
  { id: "stripe-secret-test", title: "Stripe test secret key", regex: /\bsk_test_[A-Za-z0-9]{16,}/g, severity: "low", sensitive: false },
  { id: "stripe-restricted", title: "Stripe restricted key (live)", regex: /\brk_live_[A-Za-z0-9]{16,}/g, severity: "high", sensitive: true },
  { id: "stripe-restricted-test", title: "Stripe restricted test key", regex: /\brk_test_[A-Za-z0-9]{16,}/g, severity: "low", sensitive: false },
  { id: "aws-access-key", title: "AWS access key id", regex: /\bAKIA[0-9A-Z]{16}\b/g, severity: "high", sensitive: true },
  { id: "google-api-key", title: "Google API key", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g, severity: "high", sensitive: true,
    accept: (_m, content, index) => !inFirebaseConfig(content, index) },
  { id: "openai-project-key", title: "OpenAI project API key", regex: /\bsk-proj-[A-Za-z0-9_-]{32,}/g, severity: "high", sensitive: true },
  { id: "openai-key", title: "OpenAI API key", regex: /\bsk-[A-Za-z0-9]{32,}\b/g, severity: "high", sensitive: true },
  { id: "anthropic-key", title: "Anthropic API key", regex: /\bsk-ant-[A-Za-z0-9\-_]{20,}/g, severity: "high", sensitive: true },
  { id: "github-pat", title: "GitHub personal access token", regex: /\bghp_[A-Za-z0-9]{36}\b/g, severity: "high", sensitive: true },
  { id: "github-fine-grained-pat", title: "GitHub fine-grained token", regex: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/g, severity: "high", sensitive: true },
  { id: "github-oauth", title: "GitHub OAuth/app token", regex: /\bgh[ousr]_[A-Za-z0-9]{36}\b/g, severity: "high", sensitive: true },
  { id: "slack-token", title: "Slack token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, severity: "high", sensitive: true },
  { id: "npm-token", title: "npm access token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "high", sensitive: true },
  { id: "google-oauth-secret", title: "Google OAuth client secret", regex: /\bGOCSPX-[A-Za-z0-9_-]{20,}/g, severity: "high", sensitive: true },
  { id: "sendgrid-key", title: "SendGrid API key", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: "high", sensitive: true },
  { id: "private-key-block", title: "Private key block", regex: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, severity: "critical", sensitive: true },
  // A JWT is base64url, so "service_role" never appears in clear: decode the
  // payload and keep only tokens whose role is service_role (bypasses RLS).
  { id: "supabase-service-role", title: "Supabase service_role JWT", regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g, severity: "critical", sensitive: true,
    accept: (m) => jwtPayload(m)?.role === "service_role" },
  { id: "supabase-secret-key", title: "Supabase secret API key", regex: /\bsb_secret_[A-Za-z0-9_-]{20,}/g, severity: "critical", sensitive: true },
];

// Only scan text-like files, and skip anything large or binary.
const TEXT_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json", ".html", ".css", ".map", ".txt", ".env"]);
const MAX_BYTES = 8 * 1024 * 1024;

const walk = (dir: string) => walkFiles(dir, { accept: (name) => TEXT_EXT.has(extOf(name)) });

function redact(secret: string): string {
  if (secret.length <= 10) return secret.slice(0, 2) + "***";
  return `${secret.slice(0, 6)}...${secret.slice(-4)} (${secret.length} chars)`;
}

const LIT = String.raw`(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')`;
const unquote = (lit: string): string => {
  const body = lit.slice(1, -1);
  return body.replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)/g, (_m, e: string) =>
    (e[0] === "x" && e.length === 3) || (e[0] === "u" && e.length === 5) ? String.fromCharCode(parseInt(e.slice(1), 16)) : e === "n" ? "\n" : e);
};
const printable = (s: string) => /^[\x20-\x7e\r\n\t]+$/.test(s);

/**
 * Views of the source where a key hidden from plain scanners becomes readable:
 * concatenated literals ("sk_li" + "ve_..."), ["a","b"].join(""), atob("..."),
 * \x / \u escapes, and "...".split("").reverse().join(""). Literals only: no
 * code is evaluated.
 */
export function decodedViews(content: string): { text: string; index: number; method: string }[] {
  const out: { text: string; index: number; method: string }[] = [];
  const lits = (s: string) => [...s.matchAll(new RegExp(LIT, "g"))].map((m) => unquote(m[0]));
  for (const m of content.matchAll(new RegExp(`${LIT}(?:\\s*\\+\\s*${LIT})+`, "g"))) out.push({ text: lits(m[0]).join(""), index: m.index!, method: "string concatenation" });
  for (const m of content.matchAll(new RegExp(`\\[\\s*(${LIT}(?:\\s*,\\s*${LIT})+)\\s*,?\\s*\\]\\s*\\.join\\(\\s*(?:""|'')\\s*\\)`, "g"))) out.push({ text: lits(m[1]!).join(""), index: m.index!, method: "array join" });
  for (const m of content.matchAll(/\batob\(\s*["']([A-Za-z0-9+/=]{16,})["']\s*\)/g)) {
    const t = Buffer.from(m[1]!, "base64").toString("utf8");
    if (printable(t)) out.push({ text: t, index: m.index!, method: "base64 (atob)" });
  }
  for (const m of content.matchAll(new RegExp(LIT, "g"))) {
    if (!/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})/.test(m[0])) continue;
    out.push({ text: unquote(m[0]), index: m.index!, method: "escaped characters" });
  }
  for (const m of content.matchAll(new RegExp(`(${LIT})\\.split\\(\\s*(?:""|'')\\s*\\)\\.reverse\\(\\)\\.join\\(\\s*(?:""|'')\\s*\\)`, "g"))) out.push({ text: [...unquote(m[1]!)].reverse().join(""), index: m.index!, method: "reversed string" });
  return out;
}

export const exposedSecrets: Check = {
  name: "exposed-secrets",
  title: "Secrets and private keys shipped to the client bundle",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    // The raw secret per finding, kept in memory only for the opt-in liveness call.
    const rawOf = new Map<Finding, string>();
    const root = ctx.projectDir;
    for (const file of walk(root)) {
      let size = 0;
      try {
        size = statSync(file).size;
      } catch {
        continue;
      }
      if (size > MAX_BYTES) continue;
      let content: string;
      try {
        content = readFileSync(file, "utf8");
      } catch {
        continue;
      }
      const rel = relative(root, file);
      const add = (p: SecretPattern, secret: string, line: number, decoded?: string) => {
        const sensitive = p.sensitive !== false;
        findings.push({
          id: `exposed-secrets:${p.id}:${rel}:${line}${decoded ? ":decoded" : ""}`,
          check: "exposed-secrets",
          title: (sensitive ? `${p.title} exposed in ${rel}` : `${p.title} in ${rel}`) + (decoded ? ` (hidden by ${decoded})` : ""),
          severity: p.severity,
          state: "proven", // a deterministic regex match on a key shape is proof enough to act
          location: `${rel}:${line}`,
          description: (sensitive
            ? `A ${p.title} appears in a file under the scanned directory. If this directory is a ` +
              `client bundle, the secret is readable by anyone who opens the page.`
            : `A ${p.title} appears in ${rel}. Test-mode keys are safe to expose, so this is not an ` +
              `incident, but shipping any key to the client is a habit worth breaking.`) +
            (decoded ? ` It is split or encoded in the source (${decoded}), which hides it from plain scanners but not from anyone running the code.` : ""),
          remediation: sensitive
            ? `Rotate this credential now (assume it is compromised), then move it server-side. ` +
              `Client code should only ever hold publishable keys.`
            : `No rotation needed for a test key. Prefer a publishable key in client code, and keep ` +
              `even test secrets out of the bundle.`,
          proof: decoded
            ? { method: `deterministic regex match on a known key format, after decoding (${decoded})`, replay: `sed -n '${line}p' "${rel}"`, evidence: redact(secret) }
            : { method: "deterministic regex match on a known key format", replay: `grep -nE '${p.regex.source}' "${rel}"`, evidence: redact(secret) },
          regressionHint:
            `Add a CI step that greps the build output for ${p.id} and fails if present.`,
        });
        rawOf.set(findings[findings.length - 1]!, secret);
      };
      const inRaw = new Set<string>();
      for (const p of PATTERNS) {
        p.regex.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = p.regex.exec(content)) !== null) {
          if (p.accept && !p.accept(m[0], content, m.index)) continue;
          if (isPlaceholder(m[0])) continue;
          inRaw.add(m[0]);
          add(p, m[0], content.slice(0, m.index).split("\n").length);
        }
      }
      // Keys split or encoded in the source: the same detectors on decoded views.
      for (const v of decodedViews(content)) {
        for (const p of PATTERNS) {
          p.regex.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = p.regex.exec(v.text)) !== null) {
            // Already reported when a piece alone matched (a long first half): same key, one finding.
            if (isPlaceholder(m[0]) || [...inRaw].some((r) => m![0].includes(r) || r.includes(m![0]))) continue;
            if (p.accept && !p.accept(m[0], v.text, m.index)) continue;
            inRaw.add(m[0]);
            add(p, m[0], content.slice(0, v.index).split("\n").length, v.method);
          }
        }
      }
    }
    // Opt-in liveness: ask each key's own provider whether it still works.
    const verify = !!(ctx.options["exposed-secrets"] as { verify?: boolean } | undefined)?.verify;
    if (verify) {
      const cache = new Map<string, Promise<{ liveness: Liveness; status?: number; host?: string; note?: string }>>();
      for (const f of findings) {
        const raw = rawOf.get(f);
        const pattern = f.id.split(":")[1]!;
        if (!raw || !verifierHost(pattern)) continue;
        if (!cache.has(raw)) cache.set(raw, checkLiveness(pattern, raw, ctx.scope));
        const r = await cache.get(raw)!;
        if (r.liveness === "unknown") {
          if (r.host && !ctx.scope.isHostAllowed(`https://${r.host}/`)) ctx.log(`exposed-secrets: liveness of ${pattern} skipped, declare ${r.host} in scope.allowedHosts to check it`);
          continue;
        }
        if (r.liveness === "active") {
          f.title = `${f.title} (key works right now)`;
          f.description = `${f.description} Crenel checked with one read-only call to ${r.host}: the key authenticates (HTTP ${r.status}).${r.note ? ` ${r.note}` : ""}`;
        } else {
          f.title = `${f.title} (revoked)`;
          f.severity = "low";
          f.description = `${f.description} Crenel checked with one read-only call to ${r.host}: the key is revoked (HTTP ${r.status}). Remove it from the bundle anyway.`;
        }
        if (f.proof) f.proof.evidence = `${f.proof.evidence ?? ""} · liveness: ${r.liveness} (HTTP ${r.status} from ${r.host})`;
      }
    }

    ctx.log(`exposed-secrets: scanned ${root}, ${findings.length} match(es)`);
    return findings;
  },
};
