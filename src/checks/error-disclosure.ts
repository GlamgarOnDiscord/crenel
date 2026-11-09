// error-disclosure: a malformed request makes the server answer with a stack
// trace — server file paths, framework internals, versions — instead of a clean
// error. That is information disclosure (CWE-209): it hands an attacker the stack,
// dependency paths and line numbers. Proven by a differential with a control: a
// malformed body returns a response carrying a stack trace that the SAME endpoint
// with a benign body does not. Generic across runtimes (Node `at fn (/path:line)`,
// Python `Traceback`, Java `.java:line`), no target signature — the trigger is a
// truncated JSON body, the oracle is the stack-trace shape, the control removes
// pages that always look like that.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";

interface Ep { url: string; method?: string }

export const ERR_ENDPOINTS: Ep[] = [
  { url: "/rest/user/login" }, { url: "/api/login" }, { url: "/login" },
  { url: "/api/users" }, { url: "/api/auth/login" }, { url: "/graphql" },
  { url: "/api" }, { url: "/rest" }, { url: "/signup" }, { url: "/register" },
];

// Stack-trace signals across runtimes. Several must co-occur (or a Python/Java
// traceback header appear) so a page that merely mentions a path is not a hit.
const SIGNALS = [
  /\bat\s+[\w.$<>[\] ]+\s*\(?\/?[\w./\\-]+:\d+:\d+\)?/, // Node: at fn (/path:line:col)
  /node_modules[/\\]/i,
  /\.(js|ts|mjs|cjs|py|rb|php|go):\d+/i,
  /\bat [\w.$]+\([\w.$/]+\.java:\d+\)/, // Java frame
];
const HARD = /Traceback \(most recent call last\)|File "[^"]+", line \d+|org\.springframework|System\.Web\.HttpException/i;

/** True when the body looks like a server stack trace. Pure, tested. */
export function hasStackTrace(body: string): boolean {
  if (HARD.test(body)) return true;
  return SIGNALS.filter((re) => re.test(body)).length >= 2;
}

export const errorDisclosure: Check = {
  name: "error-disclosure",
  title: "Stack trace / internal error disclosed on a malformed request",
  readOnly: false, // sends a crafted (malformed) POST body: active gate, though it writes nothing
  async run(ctx: CheckContext): Promise<Finding[]> {
    const opts = (ctx.options["error-disclosure"] ?? {}) as { enabled?: boolean; endpoints?: Ep[] };
    if (opts.enabled !== true || !ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    ctx.scope.assertActiveAllowed("error-disclosure (malformed request probes)");
    const endpoints = opts.endpoints ?? ERR_ENDPOINTS;
    const post = async (p: string, body: string, method = "POST") => {
      try { const r = await safeFetch(base + p, ctx.scope, { method, headers: { "content-type": "application/json" }, body, maxBytes: 128 * 1024 }); return { status: r.status, body: r.body }; } catch { return { status: 0, body: "" }; }
    };
    const findings: Finding[] = [];
    for (const ep of endpoints) {
      const method = ep.method ?? "POST";
      // Benign body: valid JSON. The control must NOT carry a stack trace.
      const benign = await post(ep.url, "{}", method);
      if (hasStackTrace(benign.body)) continue; // the endpoint always shows a stack: not caused by us (or not reachable)
      // Malformed body: truncated JSON triggers the parser error path.
      const malformed = await post(ep.url, '{"x":', method);
      if (!hasStackTrace(malformed.body)) continue;
      const paths = [...new Set([...malformed.body.matchAll(/(?:\/[\w.-]+){2,}\.(?:js|ts|mjs|cjs|py|rb|php|go):\d+/g)].map((m) => m[0]))].slice(0, 5);
      findings.push({
        id: `error-disclosure:${ep.url}`,
        check: "error-disclosure",
        title: `Stack trace disclosed on a malformed request to ${ep.url}`,
        severity: "medium",
        state: "proven",
        location: base + ep.url,
        description: `A malformed JSON body to ${ep.url} (HTTP ${malformed.status}) returns a server stack trace that a benign body does not${paths.length ? ` (e.g. ${paths.join(", ")})` : ""}. It leaks file paths, framework and dependency internals useful for further attacks.`,
        remediation: "Return a generic error to clients and log the detail server-side; disable the development error handler in production.",
        proof: { method: "live differential on staging: benign body (no stack) vs malformed body (stack trace)", replay: `curl -i -X ${method} -H 'content-type: application/json' --data '{"x":' '${base}${ep.url}'`, evidence: `malformed HTTP ${malformed.status} carried a stack trace; benign HTTP ${benign.status} did not` },
        regressionHint: `After deploy, a malformed body to ${ep.url} must not return a stack trace.`,
      });
      break; // the error handler is global: one proof is the finding, not one per endpoint
    }
    if (findings.length === 0) ctx.log("error-disclosure: no stack trace leaked on a malformed request");
    return findings;
  },
};
