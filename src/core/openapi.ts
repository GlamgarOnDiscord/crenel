// Fill the authorization matrix from an OpenAPI file instead of by hand (the
// method of AuthProbe and Schemathesis). Every GET route with exactly one path
// parameter is a candidate object route: /projects/{projectId} becomes
// { name: "projects", path: "/projects/:id", methods: ["GET"] }. Routes with
// several parameters or none are skipped: the matrix replays one object id at a
// time. Only GET is imported; writes are never probed.

import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";

export interface ImportedResource { name: string; path: string; methods: string[]; public?: boolean }

interface OpenApiDoc {
  servers?: { url?: string }[];
  basePath?: string;
  paths?: Record<string, Record<string, { security?: unknown[]; operationId?: string } | unknown>>;
  security?: unknown[];
}

/** Path prefix declared by the spec's first server (v3) or basePath (v2), e.g. "/api". */
function prefixOf(doc: OpenApiDoc): string {
  const raw = doc.servers?.[0]?.url ?? doc.basePath ?? "";
  let p = raw;
  try { p = new URL(raw, "http://x").pathname; } catch { /* keep raw */ }
  return p === "/" ? "" : p.replace(/\/+$/, "");
}

export function resourcesFromOpenApi(doc: OpenApiDoc): ImportedResource[] {
  const out: ImportedResource[] = [];
  const names = new Set<string>();
  const prefix = prefixOf(doc);
  for (const [route, ops] of Object.entries(doc.paths ?? {})) {
    const params = route.match(/\{[^}]+\}/g) ?? [];
    const get = (ops as Record<string, unknown>)?.get as { security?: unknown[] } | undefined;
    if (params.length !== 1 || !get) continue;
    // The object segment comes right before the parameter: /orgs/x/projects/{id} -> "projects".
    const before = route.slice(0, route.indexOf(params[0]!)).split("/").filter(Boolean);
    let name = (before.at(-1) ?? "resource").replace(/[^\w-]/g, "") || "resource";
    for (let i = 2; names.has(name); i++) name = `${before.at(-1) ?? "resource"}-${i}`;
    names.add(name);
    // An operation with `security: []` declares itself public: a trust boundary, not a leak.
    const isPublic = Array.isArray(get.security) && get.security.length === 0;
    out.push({ name, path: prefix + route.replace(params[0]!, ":id"), methods: ["GET"], ...(isPublic ? { public: true } : {}) });
  }
  return out;
}

export function loadOpenApi(file: string): ImportedResource[] {
  const raw = readFileSync(file, "utf8");
  const doc = (file.endsWith(".json") ? JSON.parse(raw) : parseYaml(raw)) as OpenApiDoc;
  return resourcesFromOpenApi(doc);
}
