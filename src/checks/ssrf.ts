// ssrf: server code that fetches a URL taken from the request. The caller can
// then point the server at cloud metadata (169.254.169.254), localhost admin
// panels or internal services. Every AI coding agent tested by Tenzai (2026)
// introduced one. Deterministic and offline: a variable assigned from request
// input (query, params, body, searchParams) flows into fetch/axios/got in the
// same file, and the file shows no host allowlist. A lead, never proof: the
// taint tracking is a heuristic, not a data-flow analysis.

import { readFileSync, statSync } from "node:fs";

import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, extOf, isCommentedAt, relative } from "../core/walk.js";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", "public"]);
const SCAN = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

const SOURCE = String.raw`(?:searchParams\.get\(|\b(?:req|request|ctx|c)\.(?:query|params|body)\b|\bc\.req\.(?:query|param|json)\(|\breq\.param\()`;
// const target = new URL(req.url).searchParams.get("url")  /  const { url } = req.query
const ASSIGN = new RegExp(String.raw`(?:const|let|var)\s+(?:\{\s*([\w\s,]+)\}|(\w+))\s*=\s*[^;\n]*` + SOURCE, "g");
const SINK = String.raw`\b(?:fetch|axios(?:\.(?:get|post|request))?|got|request|http\.get|https\.get|undici\.request)\s*\(\s*(?:new\s+URL\s*\(\s*)?`;
const DIRECT = new RegExp(SINK + SOURCE, "g");
// Signs the author restricted the destination: we do not flag those files.
const ALLOWLIST = /allow(?:ed)?(?:_|-)?(?:list|hosts?|origins?|domains?)|ALLOWED|\.hostname\s*(?:===|!==|==)|\.(?:has|includes)\(\s*\w+\.hostname/i;

const lineOf = (text: string, index: number) => text.slice(0, index).split("\n").length;

export const ssrf: Check = {
  name: "ssrf",
  title: "Server-side request to a URL taken from the request (SSRF)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const accept = (name: string) => SCAN.has(extOf(name));
    for (const file of walkFiles(ctx.projectDir, { skipDirs: SKIP, accept })) {
      let text: string;
      try {
        if (statSync(file).size > 1024 * 1024) continue;
        text = readFileSync(file, "utf8");
      } catch { continue; }
      if (ALLOWLIST.test(text)) continue;
      const rel = relative(ctx.projectDir, file) || file;
      const hits: number[] = [];
      for (const m of text.matchAll(DIRECT)) if (!isCommentedAt(text, m.index!)) hits.push(m.index!);
      for (const m of text.matchAll(ASSIGN)) {
        if (isCommentedAt(text, m.index!)) continue;
        const names = (m[1] ?? m[2] ?? "").split(",").map((s) => s.trim().split(/\s*:\s*/).pop()!).filter(Boolean);
        for (const n of names) {
          const sink = new RegExp(SINK + String.raw`\b${n}\b`, "g");
          sink.lastIndex = m.index! + m[0].length;
          const s = sink.exec(text);
          if (s && !isCommentedAt(text, s.index)) hits.push(s.index);
        }
      }
      if (!hits.length) continue;
      const line = lineOf(text, Math.min(...hits));
      findings.push({
        id: `ssrf:${rel}`,
        check: "ssrf",
        title: `Server fetches a URL taken from the request: ${rel}`,
        severity: "high",
        state: "unproven",
        location: `${rel}:${line}`,
        description: `${rel} passes a URL that comes from the request to a server-side HTTP client, with no host allowlist in the file. A caller can make the server reach cloud metadata, localhost or internal services.`,
        remediation: "Parse the URL, require https, and allow only an explicit list of hosts; resolve the host and refuse private, loopback and link-local addresses before connecting; never follow redirects to another host.",
        proof: { method: "request input flows into fetch/axios/got in the same file, no allowlist", replay: `sed -n '${line}p' "${rel}"` },
        regressionHint: `Test: call the route with url=http://169.254.169.254/ and with url=http://127.0.0.1/ and expect a refusal.`,
      });
    }
    ctx.log(`ssrf: ${findings.length} finding(s)`);
    return findings;
  },
};
