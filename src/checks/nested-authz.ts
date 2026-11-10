// nested-authz: cross-tenant authorization on a NESTED resource, the gap the flat
// authz-matrix leaves open. Flat BOLA replaces a single :id; many real breaks live
// one level down — /orgs/:org/projects/:id, /posts/:pid/comments/:id — where the
// server checks the parent but trusts the leaf, so account A reads B's leaf object
// by walking B's whole path. Same proven oracle as authz-matrix (authzOracle): a
// 2xx is not proof; the attacker's body must carry the owner's marker (or match the
// owner's own response), a negative control (the SAME path with a non-existent LEAF,
// parents kept) must not answer the same way, and an anonymous caller must be
// refused (a public nested route is a lead, never a proven BOLA).
//
// No target string: paths and per-segment ids are operator config; the proof is the
// differential with its controls. Live probe only, gated like authz-matrix: crafted
// cross-tenant GETs need allowActiveTesting on an owned host.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { randomBytes } from "node:crypto";
import { safeFetch } from "../core/net.js";
import { authzOracle } from "../agent/validators.js";
import { sameIdentity } from "./authz-matrix.js";

type Auth = { token?: string; cookie?: string; headers?: Record<string, string> };
interface AccountSpec extends Auth { marker?: string }
interface NestedResource {
  /** e.g. "project" */
  name: string;
  /** Path template with one placeholder per owned segment, e.g. "/orgs/:org/projects/:id". */
  path: string;
  /** The owned LEAF placeholder (the object whose isolation is tested). Default: the
   * last placeholder in `path`. The control swaps only this one for a bogus id. */
  leaf?: string;
  /** Segment value per account: segments[placeholder][accountKey]. B must have every
   * segment (it owns the whole chain). A/C are optional (used only if declared). */
  segments: Record<string, { a?: string; b?: string; c?: string }>;
}
interface Opts { accounts?: { a?: AccountSpec; b?: AccountSpec; c?: AccountSpec }; resources?: NestedResource[] }

const authHeaders = (a?: Auth): Record<string, string> =>
  a ? { ...(a.token ? { authorization: `Bearer ${a.token}` } : {}), ...(a.cookie ? { cookie: a.cookie } : {}), ...(a.headers ?? {}) } : {};
const hasAuth = (a?: Auth): boolean => !!(a && (a.token || a.cookie || (a.headers && Object.keys(a.headers).length > 0)));
const placeholders = (path: string): string[] => [...path.matchAll(/:([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]!);

/** Fill every placeholder in `path` from `pick`; returns null if any is missing. */
function fill(path: string, pick: (name: string) => string | undefined): string | null {
  let out = path, ok = true;
  out = out.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, (_, name: string) => {
    const v = pick(name);
    if (v === undefined) { ok = false; return _; }
    return encodeURIComponent(v);
  });
  return ok ? out : null;
}

export const nestedAuthz: Check = {
  name: "nested-authz",
  title: "Cross-tenant authorization on a nested resource (the server trusts the leaf id)",
  readOnly: true, // GET-only; the live cross-tenant probe is gated separately
  async run(ctx: CheckContext): Promise<Finding[]> {
    const cfg = (ctx.options["nested-authz"] ?? {}) as Opts;
    const resources = cfg.resources ?? [];
    const accounts = cfg.accounts ?? {};
    const findings: Finding[] = [];
    if (resources.length === 0) { ctx.log("nested-authz: no nested resources declared"); return findings; }
    if (!ctx.stagingUrl || !hasAuth(accounts.a) || !hasAuth(accounts.b)) {
      ctx.log("nested-authz: needs a staging URL and two authenticated accounts (a, b)");
      return findings;
    }
    // Same guard as authz-matrix: if A and B are one identity, a "cross-tenant" read
    // is B reading its own object and proves nothing.
    const same = sameIdentity(accounts.a?.token, accounts.b?.token)
      || (accounts.a?.cookie && accounts.a.cookie === accounts.b?.cookie ? "use the same session cookie" : null);
    if (same) { ctx.log(`nested-authz: accounts A and B are the same identity (${same})`); return findings; }

    ctx.scope.assertActiveAllowed("nested-authz (live cross-tenant probe)");
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const get = (url: string, auth?: Auth) =>
      safeFetch(url, ctx.scope, { method: "GET", headers: authHeaders(auth) }).then((r) => ({ status: r.status, body: r.body }));

    for (const r of resources) {
      const names = placeholders(r.path);
      if (names.length < 2) { ctx.log(`nested-authz: ${r.name} path is not nested (needs >= 2 segments)`); continue; }
      const leaf = r.leaf ?? names[names.length - 1]!;
      if (!names.includes(leaf)) { ctx.log(`nested-authz: ${r.name} leaf "${leaf}" is not a path segment`); continue; }
      // B's full chain: every segment resolved from B's values.
      const ownerUrlPath = fill(r.path, (n) => r.segments[n]?.b);
      if (ownerUrlPath === null) { ctx.log(`nested-authz: ${r.name} is missing a B value for some segment`); continue; }
      // The attacker walks B's exact chain (B's parents and B's leaf), as A.
      const attackerUrl = base + ownerUrlPath;
      // Control: B's chain with a non-existent LEAF (parents kept). Proves the leaf is
      // the boundary, not the parent — and that the route does not answer everything.
      const bogus = `crenel-nonexistent-${randomBytes(6).toString("hex")}`;
      const controlPath = fill(r.path, (n) => (n === leaf ? bogus : r.segments[n]?.b));
      if (controlPath === null) continue;
      try {
        const owner = await get(attackerUrl, accounts.b);
        const attacker = await get(attackerUrl, accounts.a);
        const control = await get(base + controlPath, accounts.a);
        const anon = await get(attackerUrl);
        const leafId = r.segments[leaf]?.b;
        const markers = [accounts.b?.marker ?? "", leafId ?? ""].filter(Boolean);
        const v = authzOracle({ attacker, owner, control, ownerMarkers: markers });
        if (v.verdict !== "leak") { ctx.log(`nested-authz: ${r.name} -> ${v.verdict} (${v.reason})`); continue; }
        // A public nested route (anonymous allowed) is a lead, never a proven BOLA.
        if (!(anon.status === 401 || anon.status === 403 || anon.status === 404)) {
          ctx.log(`nested-authz: ${r.name} leak but anonymous also reads it (HTTP ${anon.status}): public route, lead only`);
          continue;
        }
        findings.push({
          id: `nested-authz:${r.name}:${r.path}`,
          check: "nested-authz",
          title: `Cross-tenant read of a nested ${r.name} at ${r.path}`,
          severity: "high",
          state: "proven",
          location: attackerUrl,
          description: `Account A read account B's ${r.name} by walking B's full nested path ${r.path} (${v.reason}). The server authorizes the parent segment but trusts the leaf id, so one tenant reaches another's nested object. An anonymous caller is refused (HTTP ${anon.status}), so this is a real authorization boundary that A crosses.`,
          remediation: `Authorize the LEAF object against the caller, not only its parent: check that ${leaf} belongs to the caller (or to a parent the caller owns) before returning it. A valid parent must never imply access to an arbitrary child.`,
          proof: {
            method: "live differential on staging: owner baseline (B), attacker read (A) of B's nested path, negative control (A, same path with a non-existent leaf), anonymous refused",
            replay: `curl -i${accounts.a?.token ? " -H 'authorization: Bearer <A_TOKEN>'" : ""} '${attackerUrl}'  # A reading B's nested ${r.name}`,
            evidence: `attacker HTTP ${attacker.status} (${v.reason}); control (bogus ${leaf}) HTTP ${control.status}; owner HTTP ${owner.status}; anonymous HTTP ${anon.status}`,
          },
          regressionHint: `After the fix, A requesting B's nested ${r.path} must return 401/403/404, while B still reads its own.`,
        });
      } catch (err) {
        ctx.log(`nested-authz: ${r.name} failed: ${(err as Error).message}`);
      }
    }
    ctx.log(`nested-authz: ${findings.filter((f) => f.state === "proven").length} proven`);
    return findings;
  },
};
