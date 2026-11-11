// function-authz: broken function-level authorization (OWASP API5 / BFLA), the
// deterministic sibling of the model-driven explore.bfla. A normal account reaches
// a function meant for a privileged one — reading the full user list, hitting an
// admin endpoint, triggering a privileged action. "Privileged" cannot be guessed,
// so both a privileged account P and a normal account A are DECLARED; the check
// only proves the mechanism with bflaOracle: P reaches the function, an anonymous
// caller is refused (a real boundary, not a public endpoint), a nonsense variant as
// A is refused (A does not get 2xx for everything), and A reaches the SAME function
// P does (for a read, the same privileged view). That is privilege escalation to an
// admin-only function.
//
// No target string: paths and accounts are operator config; the proof is the
// differential across P, A, anonymous and a control. GET-only; the live probe is
// gated like authz-matrix (crafted privileged requests need allowActiveTesting).

import type { Check, CheckContext, Finding } from "../core/types.js";
import { randomBytes } from "node:crypto";
import { safeFetch } from "../core/net.js";
import { bflaOracle } from "../agent/bfla.js";
import { sameIdentity } from "./authz-matrix.js";

type Auth = { token?: string; cookie?: string; headers?: Record<string, string> };
interface PrivFunction {
  /** e.g. "user-list" */
  name: string;
  /** The privileged function's path, e.g. "/api/Users" or "/rest/admin/...". */
  path: string;
  /** A read returns the privileged VIEW (A's body must match P's); a non-read action
   * only needs both to be accepted. Default true. */
  isRead?: boolean;
  /** Control: a path a discriminating server refuses for the normal account.
   * Default: `path` with a non-existent trailing segment. */
  control?: string;
}
interface Opts { accounts?: { privileged?: Auth; normal?: Auth }; functions?: PrivFunction[] }

const authHeaders = (a?: Auth): Record<string, string> =>
  a ? { ...(a.token ? { authorization: `Bearer ${a.token}` } : {}), ...(a.cookie ? { cookie: a.cookie } : {}), ...(a.headers ?? {}) } : {};
const hasAuth = (a?: Auth): boolean => !!(a && (a.token || a.cookie || (a.headers && Object.keys(a.headers).length > 0)));

export const functionAuthz: Check = {
  name: "function-authz",
  title: "Broken function-level authorization (a normal account reaches a privileged function)",
  readOnly: true, // GET-only; the live privileged probe is gated separately
  async run(ctx: CheckContext): Promise<Finding[]> {
    const cfg = (ctx.options["function-authz"] ?? {}) as Opts;
    const functions = cfg.functions ?? [];
    const accounts = cfg.accounts ?? {};
    const findings: Finding[] = [];
    if (functions.length === 0) { ctx.log("function-authz: no privileged functions declared"); return findings; }
    if (!ctx.stagingUrl || !hasAuth(accounts.privileged) || !hasAuth(accounts.normal)) {
      ctx.log("function-authz: needs a staging URL, a privileged account and a normal account");
      return findings;
    }
    // If the privileged and normal accounts are one identity, "A reaches P's
    // function" is just P reading its own: prove nothing.
    const same = sameIdentity(accounts.privileged?.token, accounts.normal?.token)
      || (accounts.privileged?.cookie && accounts.privileged.cookie === accounts.normal?.cookie ? "use the same session cookie" : null);
    if (same) { ctx.log(`function-authz: the privileged and normal accounts are the same identity (${same})`); return findings; }

    ctx.scope.assertActiveAllowed("function-authz (live privileged probe)");
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const get = (path: string, auth?: Auth) =>
      safeFetch(base + path, ctx.scope, { method: "GET", headers: authHeaders(auth) }).then((r) => ({ status: r.status, body: r.body }));

    for (const f of functions) {
      if (!f.name || !f.path) { ctx.log("function-authz: a function needs name and path"); continue; }
      const isRead = f.isRead ?? true;
      const controlPath = f.control ?? `${f.path.replace(/\/+$/, "")}/crenel-nonexistent-${randomBytes(6).toString("hex")}`;
      try {
        const privileged = await get(f.path, accounts.privileged);
        const normal = await get(f.path, accounts.normal);
        const anon = await get(f.path);
        const control = await get(controlPath, accounts.normal);
        const v = bflaOracle({ isRead, privileged, normal, anon, control });
        if (v.verdict !== "bfla") { ctx.log(`function-authz: ${f.name} -> ${v.verdict} (${v.reason})`); continue; }
        findings.push({
          id: `function-authz:${f.name}:${f.path}`,
          check: "function-authz",
          title: `Broken function-level authorization at ${f.path} (${f.name})`,
          severity: "high",
          state: "proven",
          location: base + f.path,
          description: `A normal account reaches ${f.path}, a function the privileged account uses (${v.reason}). This is a privilege escalation to an admin-only function: a regular user reaches the admin section / privileged operation. An anonymous caller is refused (HTTP ${anon.status}), so this is a real authorization boundary the normal account crosses.`,
          remediation: `Enforce the role or permission on ${f.path} server-side for every caller: a valid session must not imply access to a privileged function. Check the caller's role before serving it, not only that they are authenticated.`,
          proof: {
            method: "live differential on staging: privileged account reaches the function, normal account reaches the same (same view for a read), anonymous refused, a nonsense variant as the normal account refused",
            replay: `curl -i${accounts.normal?.token ? " -H 'authorization: Bearer <NORMAL_TOKEN>'" : ""} '${base + f.path}'  # a normal account reaching a privileged function`,
            evidence: `privileged HTTP ${privileged.status}; normal HTTP ${normal.status}; anonymous HTTP ${anon.status}; control HTTP ${control.status}`,
          },
          regressionHint: `After the fix, the normal account requesting ${f.path} must return 401/403, while the privileged account still reaches it.`,
        });
      } catch (err) {
        ctx.log(`function-authz: ${f.name} failed: ${(err as Error).message}`);
      }
    }
    ctx.log(`function-authz: ${findings.filter((f) => f.state === "proven").length} proven`);
    return findings;
  },
};
