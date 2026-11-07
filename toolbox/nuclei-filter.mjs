// Nuclei template allowlist for the Crenel toolbox image.
//
// Runs at image build time (`node nuclei-filter.mjs <templates-dir>`): every
// template that does not pass `isAllowedTemplate` is DELETED from the image, so
// the nuclei binary inside the container can only ever load templates that are
// known to be non-intrusive. Crenel also passes -tags/-etags at run time, and
// the egress proxy refuses non read-only methods on plain HTTP: three layers.
//
// The rule is conservative by design: when a template is ambiguous, it goes.
//   - only http/ templates, in four directories (exposures, misconfiguration,
//     technologies, exposed-panels): no CVE exploits, no fuzzing, no default
//     logins, no OSINT (which queries third-party sites), no takeovers;
//   - at least one tag from ALLOWED_TAGS, none from DENIED_TAGS;
//   - top-level keys limited to id/info/http (no code, javascript, dns, network,
//     ssl, headless, flow, workflows, self-contained);
//   - inside http: no raw requests (any method), no payloads/fuzzing/attack, no
//     body, no unsafe mode, no pipelining/race, only GET or HEAD, no out-of-band
//     interaction (interactsh), no absolute URL (a template must target the
//     scanned host, never a fixed third-party one).
//
// No dependency: it must run in a bare node build stage. Tested by
// src/toolbox/nuclei-filter.test.ts.

import { readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

export const ALLOWED_DIRS = ["exposures", "misconfiguration", "technologies", "exposed-panels"];
export const ALLOWED_TAGS = ["exposure", "misconfig", "tech", "panel", "config", "detect", "discovery", "disclosure", "headers", "files", "logs", "debug"];
export const DENIED_TAGS = [
  "intrusive", "dos", "fuzz", "fuzzing", "bruteforce", "brute-force", "default-login", "sqli", "xss", "rce", "lfi", "rfi",
  "ssrf", "injection", "oast", "oob", "traversal", "takeover", "osint", "upload", "auth-bypass", "cve", "kev", "vkev",
  "exploit", "deserialization", "xxe", "ssti", "redirect", "crlf", "spray", "token-spray", "credential-stuffing",
];
const TOP_LEVEL_OK = new Set(["id", "info", "http", "requests"]);
const HTTP_KEYS_DENIED = ["raw", "payloads", "fuzzing", "attack", "body", "unsafe", "pipeline", "pipeline-concurrent-connections", "race", "race_count", "threads", "self-contained", "req-condition"];
const SAFE_METHODS = new Set(["GET", "HEAD"]);

/** Decide one template. `rel` is its path relative to the templates root, with "/" separators. */
export function isAllowedTemplate(text, rel) {
  const no = (reason) => ({ ok: false, reason });
  const parts = rel.split("/");
  if (parts[0] !== "http") return no("not an http template");
  if (!ALLOWED_DIRS.includes(parts[1] ?? "")) return no(`directory ${parts[1]} not allowed`);
  const lines = text.split(/\r?\n/);

  // Top-level keys (column 0).
  for (const l of lines) {
    const m = l.match(/^([A-Za-z_-]+)\s*:/);
    if (m && !TOP_LEVEL_OK.has(m[1])) return no(`top-level key ${m[1]}`);
  }

  // Tags, from the info block (single line, comma separated).
  const tagLine = text.match(/^\s+tags:\s*(.+)$/m);
  const tags = tagLine ? tagLine[1].replace(/["']/g, "").split(",").map((t) => t.trim().toLowerCase()).filter(Boolean) : [];
  const denied = tags.find((t) => DENIED_TAGS.includes(t));
  if (denied) return no(`denied tag ${denied}`);
  if (!tags.some((t) => ALLOWED_TAGS.includes(t))) return no("no allowed tag");

  // The http block: from "http:" (or legacy "requests:") to the next top-level key.
  const start = lines.findIndex((l) => /^(http|requests)\s*:/.test(l));
  if (start < 0) return no("no http block");
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) if (/^[A-Za-z_-]+\s*:/.test(lines[i])) { end = i; break; }
  const block = lines.slice(start + 1, end);
  const blockText = block.join("\n");

  for (const l of block) {
    const k = l.match(/^\s*(?:-\s+)?([A-Za-z_-]+)\s*:/);
    if (k && HTTP_KEYS_DENIED.includes(k[1])) return no(`http key ${k[1]}`);
    const m = l.match(/^\s*(?:-\s+)?method\s*:\s*["']?([A-Za-z]+)/);
    if (m && !SAFE_METHODS.has(m[1].toUpperCase())) return no(`method ${m[1]}`);
  }
  if (/interactsh/i.test(blockText)) return no("out-of-band interaction");
  if (/^\s*(?:-\s+)?(?:unsafe|self-contained)\s*:\s*true/m.test(blockText)) return no("unsafe mode");
  // Path entries must start from the scanned target.
  for (const l of block) {
    const p = l.match(/^\s*-\s+["']?(.*?)["']?\s*$/);
    if (p && /^(https?:)?\/\//i.test(p[1])) return no("absolute URL to a fixed host");
  }
  return { ok: true, reason: "allowed" };
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

/** Delete every template that is not allowed. Returns the counts and writes ALLOWLIST.txt. */
export function pruneTemplates(root) {
  let kept = 0, removed = 0;
  const allow = [];
  for (const p of walk(root)) {
    const rel = relative(root, p).split(sep).join("/");
    if (!p.endsWith(".yaml") && !p.endsWith(".yml")) {
      // Keep only what nuclei needs to start: no workflows, helpers, scripts.
      if (rel !== ".templates-config.json") rmSync(p, { force: true });
      continue;
    }
    const v = isAllowedTemplate(readFileSync(p, "utf8"), rel);
    if (v.ok) { kept++; allow.push(rel); } else { removed++; rmSync(p, { force: true }); }
  }
  writeFileSync(join(root, "ALLOWLIST.txt"), allow.sort().join("\n") + "\n");
  return { kept, removed };
}

if (process.argv[1] && process.argv[1].endsWith("nuclei-filter.mjs") && process.argv[2]) {
  const r = pruneTemplates(process.argv[2]);
  process.stdout.write(`nuclei templates: ${r.kept} kept, ${r.removed} removed\n`);
  if (r.kept === 0) process.exit(1);
}
