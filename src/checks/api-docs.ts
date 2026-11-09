// api-docs: an OpenAPI or Swagger definition served by the deployed API (the
// method of sj's "brute" mode, paths written from the frameworks' defaults).
// The spec is the API's map: every route, parameter and, often, internal and
// admin operations nobody linked from the UI. Publishing it can be deliberate
// (a public API), so the finding is low, medium when it lists admin, internal
// or debug routes. The proof is the document itself: a 200 whose body parses
// as JSON or YAML with an `openapi`/`swagger` version and a `paths` object; an
// SPA answering every path with index.html never parses as one. The routes it
// lists feed the authorization matrix suggestion. GETs on declared bases only.

import { parse as parseYaml } from "yaml";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { resourcesFromOpenApi } from "../core/openapi.js";

export const SPEC_PATHS = [
  "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
  "/api/openapi.json", "/api/swagger.json", "/api-docs", "/api-docs.json",
  "/v3/api-docs", "/v2/api-docs", "/swagger/v1/swagger.json", "/docs/openapi.json",
];
const SENSITIVE = /\/(admin|internal|debug|_?private|backoffice|staff|impersonate)(\/|$|\{)/i;

interface Spec { openapi?: string; swagger?: string; paths?: Record<string, Record<string, unknown>> }

/** The JSON object after "swaggerDoc": in a Swagger UI init script (balanced braces, strings skipped), or null. */
export function embeddedSwaggerDoc(js: string): string | null {
  const i = js.search(/"swaggerDoc"\s*:\s*\{/);
  if (i < 0) return null;
  const start = js.indexOf("{", i);
  let depth = 0, inStr = false, esc = false;
  for (let k = start; k < js.length; k++) {
    const ch = js[k];
    if (inStr) { if (esc) esc = false; else if (ch === "\\") esc = true; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') inStr = true;
    else if (ch === "{") depth++;
    else if (ch === "}" && --depth === 0) return js.slice(start, k + 1);
  }
  return null;
}

/** The body as an OpenAPI/Swagger document, or null when it is anything else. */
export function parseSpec(body: string): Spec | null {
  const t = body.trimStart();
  if (!t || t.startsWith("<")) return null;
  let doc: unknown;
  try { doc = t.startsWith("{") ? JSON.parse(t) : parseYaml(t); } catch { return null; }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;
  const d = doc as Spec;
  const version = d.openapi ?? d.swagger;
  if (typeof version !== "string" || !/^\d/.test(version)) return null;
  if (!d.paths || typeof d.paths !== "object" || Array.isArray(d.paths)) return null;
  return d;
}

const METHODS = new Set(["get", "put", "post", "delete", "patch", "head", "options"]);

export const apiDocs: Check = {
  name: "api-docs",
  title: "OpenAPI or Swagger definition served by the deployed API",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const opts = (ctx.options["api-docs"] ?? {}) as { urls?: string[]; paths?: string[] };
    const bases = [...new Set([...(ctx.stagingUrl ? [ctx.stagingUrl] : []), ...(opts.urls ?? [])].map((u) => u.replace(/\/+$/, "")))].filter((u) => ctx.scope.isHostAllowed(u));
    const out: Finding[] = [];
    for (const base of bases) {
      for (const path of opts.paths ?? SPEC_PATHS) {
        let res;
        try { res = await safeFetch(base + path, ctx.scope, { maxBytes: 4 * 1024 * 1024 }); } catch { break; }
        if (res.status !== 200) continue;
        let spec = parseSpec(res.body);
        let served = path;
        // A Swagger UI page (swagger-ui-express and similar) carries the definition in its init script.
        if (!spec && /<title>\s*Swagger UI/i.test(res.body)) {
          const init = `${path.replace(/\/+$/, "")}/swagger-ui-init.js`;
          try {
            const r2 = await safeFetch(base + init, ctx.scope, { maxBytes: 4 * 1024 * 1024 });
            const doc = r2.status === 200 ? embeddedSwaggerDoc(r2.body) : null;
            if (doc) { spec = parseSpec(doc); served = init; }
          } catch { /* no init script */ }
        }
        if (!spec) continue;
        const routes = Object.keys(spec.paths!);
        const ops = routes.reduce((n, r) => n + Object.keys(spec.paths![r] ?? {}).filter((m) => METHODS.has(m)).length, 0);
        const sensitive = routes.filter((r) => SENSITIVE.test(r));
        const objects = resourcesFromOpenApi(spec as Parameters<typeof resourcesFromOpenApi>[0]).filter((r) => !r.public);
        out.push({
          id: `api-docs:${new URL(base).host}${path}`, check: "api-docs", state: "proven",
          severity: sensitive.length ? "medium" : "low",
          title: `API definition served at ${new URL(base).host}${path} (${ops} operations${sensitive.length ? `, ${sensitive.length} admin or internal` : ""})`,
          location: base + path,
          description: `Anyone can download the ${spec.openapi ? `OpenAPI ${spec.openapi}` : `Swagger ${spec.swagger}`} definition: ${routes.length} route(s), ${ops} operation(s)${sensitive.length ? `, including ${sensitive.slice(0, 5).join(", ")}` : ""}. It is the map an attacker starts from. ${objects.length ? `${objects.length} GET route(s) take one object id; each should be in the authorization matrix (options.authz-matrix.openapi can import this file).` : ""}`.trim(),
          remediation: sensitive.length
            ? "Serve the definition only to authenticated developers, or publish a public spec without admin and internal routes. Check each admin route refuses a normal account."
            : "If the API is not public, stop serving the definition in production (or put it behind auth). If it is public, keep it, and make sure every object route is in the authorization matrix.",
          proof: { method: "GET on the declared host; the body parses as an OpenAPI/Swagger document with a version and a paths object", replay: `curl -s '${base}${served}' | head -c 300`, evidence: `HTTP 200, ${spec.openapi ? "openapi" : "swagger"} ${spec.openapi ?? spec.swagger}, ${routes.length} routes` },
          regressionHint: `If the API is private, ${path} must return 401, 403 or 404 in production.`,
        });
        break; // one definition per base: the same spec is often served at several paths
      }
    }
    ctx.log(`api-docs: ${bases.length} base(s), ${out.length} definition(s) served`);
    return out;
  },
};
