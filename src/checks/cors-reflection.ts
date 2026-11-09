// cors-reflection: the exploitable CORS shape that a static header read misses —
// the server echoes whatever Origin the caller sends into
// Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true.
// Any website the victim visits can then read their authenticated responses.
// Proven by reflection with a control: two DIFFERENT random origins are both
// echoed back with credentials, so the server reflects any origin, not an
// allowlisted one. (A static `*` or `null` with credentials is headers.ts's job;
// this is the reflected-origin case.) No target signature: random probe origins,
// the proof is the echo + credentials on two distinct values.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { randomBytes } from "node:crypto";

export const corsReflection: Check = {
  name: "cors-reflection",
  title: "CORS reflects any Origin together with credentials",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options["cors-reflection"] ?? {}) as { paths?: string[] };
    const paths = opts.paths ?? ["/", "/api", "/rest", "/api/user", "/rest/user/whoami", "/account", "/me"];
    const probe = async (p: string, origin: string) => {
      try {
        // Do not follow redirects: the CORS headers we read must belong to the
        // endpoint itself, so the stored curl replay (which does not follow
        // redirects) reproduces the same response.
        const r = await safeFetch(base + p, ctx.scope, { headers: { origin, accept: "*/*" }, followRedirects: false, maxBytes: 4096 });
        return { status: r.status, acao: (r.headers.get("access-control-allow-origin") ?? "").trim(), acac: (r.headers.get("access-control-allow-credentials") ?? "").toLowerCase().trim() };
      } catch (err) { ctx.log(`cors-reflection: probe ${p} failed: ${(err as Error).message}`); return { status: 0, acao: "", acac: "" }; }
    };
    const findings: Finding[] = [];
    for (const p of paths) {
      // Two origins on INDEPENDENT registrable domains (distinct reserved TLDs), so
      // reflecting both proves the server echoes an arbitrary origin, not merely
      // any name under one shared parent domain.
      const o1 = `https://crenel-${randomBytes(5).toString("hex")}.example`;
      const r1 = await probe(p, o1);
      if (r1.acao !== o1 || r1.acac !== "true") continue; // not the reflected-with-credentials shape
      // Control: a second, different origin must ALSO be reflected — otherwise the
      // first echo was a coincidence or an allowlisted value, not "any origin".
      const o2 = `https://${randomBytes(5).toString("hex")}-crenel.test`;
      const r2 = await probe(p, o2);
      if (r2.acao !== o2 || r2.acac !== "true") continue;
      findings.push({
        id: `cors-reflection:${p}`,
        check: "cors-reflection",
        title: `CORS reflects any Origin with credentials at ${p}`,
        severity: "high",
        state: "proven",
        location: base + p,
        description: `${p} echoes the request Origin into Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true (confirmed with two different origins). Any site the victim visits can read their authenticated responses from this endpoint.`,
        remediation: "Reflect only an allowlist of exact trusted origins, and never combine a reflected or wildcard origin with Allow-Credentials: true.",
        proof: { method: "live differential on staging: two distinct random origins, both echoed back with credentials:true", replay: `curl -i -H 'Origin: ${o1}' '${base}${p}'  # ACAO echoes the origin, ACAC: true`, evidence: `Origin ${o1} -> ACAO ${r1.acao}, ACAC ${r1.acac}; Origin ${o2} -> ACAO ${r2.acao}, ACAC ${r2.acac}` },
        regressionHint: `After deploy, an arbitrary Origin at ${p} must not be echoed into Access-Control-Allow-Origin with credentials.`,
      });
      break; // a reflecting CORS policy is global: one finding per server, not per path
    }
    if (findings.length === 0) ctx.log("cors-reflection: no origin-reflecting CORS with credentials");
    return findings;
  },
};
