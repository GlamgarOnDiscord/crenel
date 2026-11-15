// Source-aware route reconnaissance for the exploration layer. This is only a
// map: a route literal is never a finding. It gives the model reach without
// giving it authority — every claim still goes through a deterministic
// validator. Patterns describe framework mechanisms, never benchmark targets.

import { readFileSync, statSync } from "node:fs";
import { relative } from "node:path";
import { isCommentedAt, walkFiles } from "../core/walk.js";

export interface SourceRouteHint { method: string; path: string; file: string; line: number }

const SOURCE = /\.(?:[cm]?[jt]sx?|py|go|rb|java|kt|kts|php|cs)$/i;
const METHODS = "get|post|put|patch|delete|options|head";
const PATTERNS: { re: RegExp; method: (m: RegExpExecArray) => string; path: (m: RegExpExecArray) => string; uniquePath?: boolean }[] = [
  // Express, Fastify, Koa routers, Hono and similar JS/TS APIs.
  { re: new RegExp(`\\b(?:app|router|server|api|fastify)\\s*\\.\\s*(${METHODS})\\s*\\(\\s*[\"'\\x60]([^\"'\\x60]+)`, "i"), method: (m) => m[1]!, path: (m) => m[2]! },
  // Flask/FastAPI decorators and equivalent decorator-based routers.
  { re: new RegExp(`@(?:app|router|api|blueprint)\\s*\\.\\s*(${METHODS})\\s*\\(\\s*[\"']([^\"']+)`, "i"), method: (m) => m[1]!, path: (m) => m[2]! },
  { re: /@(?:app|blueprint)\s*\.\s*route\s*\(\s*["']([^"']+)["'][^)]*methods\s*=\s*\[\s*["'](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)/i, method: (m) => m[2]!, path: (m) => m[1]! },
  // Spring MVC annotations.
  { re: /@(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)/i, method: (m) => m[1]!, path: (m) => m[2]! },
  // Laravel/Symfony-style static route declarations.
  { re: new RegExp(`\\bRoute::(${METHODS})\\s*\\(\\s*[\"']([^\"']+)`, "i"), method: (m) => m[1]!, path: (m) => m[2]! },
  // Rails/Sinatra route DSL, restricted to the beginning of a statement.
  { re: new RegExp(`^\\s*(${METHODS})\\s+[\"']([^\"']+)`, "i"), method: (m) => m[1]!, path: (m) => m[2]! },
  // Go routers (gin/chi/gorilla) and the standard library.
  { re: new RegExp(`\\b(?:r|router|api|group)\\s*\\.\\s*(${METHODS})\\s*\\(\\s*[\"\\x60]([^\"\\x60]+)`, "i"), method: (m) => m[1]!, path: (m) => m[2]! },
  { re: /\bhttp\.Handle(?:Func)?\s*\(\s*["`]([^"`]+)/, method: () => "ANY", path: (m) => m[1]! },
  // Client-side calls often reveal RPC and JSON routes absent from server code.
  { re: new RegExp(`\\bfetch\\s*\\(\\s*[\"'\\x60]([^\"'\\x60]+)[\"'\\x60]\\s*,.{0,1000}?\\bmethod\\s*:\\s*[\"'\\x60](${METHODS})[\"'\\x60]`, "i"), method: (m) => m[2]!, path: (m) => m[1]! },
  { re: /\bfetch\s*\(\s*["'`]([^"'`]+)/i, method: () => "GET", path: (m) => m[1]!, uniquePath: true },
  { re: new RegExp(`\\b(?:axios|ky|client|apiClient)\\s*\\.\\s*(${METHODS})\\s*\\(\\s*[\"'\\x60]([^\"'\\x60]+)`, "i"), method: (m) => m[1]!, path: (m) => m[2]! },
];

const sanePath = (s: string): boolean => s.startsWith("/") && s.length <= 500 && !/[\r\n]/.test(s);
const NOISE_FILE = /(?:^|\/)(?:test|tests|__tests__|fixtures?|mocks?)(?:\/|$)|\.(?:test|spec)\.[cm]?[jt]sx?$/i;

function routePath(parts: string): string {
  const segments = parts.split("/").filter((part) => part && !/^\(.+\)$/.test(part) && part !== "index").map((part) => {
    const dynamic = /^\[\[?\.\.\.([^\]]+)\]\]?$/.exec(part) ?? /^\[([^\]]+)\]$/.exec(part);
    return dynamic ? `:${dynamic[1]}${part.includes("...") ? "*" : ""}` : part;
  });
  return "/" + segments.join("/");
}

/** Routes whose URL is encoded in the file layout rather than a string literal. */
function conventionRoutes(file: string, body: string): SourceRouteHint[] {
  const app = /(?:^|\/)app\/(api(?:\/.*)?)\/route\.[^.]+$/i.exec(file);
  if (app) {
    const path = routePath(app[1]!);
    const found: SourceRouteHint[] = [];
    const methods = /export\s+(?:(?:default|async)\s+)*(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/g;
    for (const m of body.matchAll(methods)) if (!isCommentedAt(body, m.index)) {
      found.push({ method: m[1]!, path, file, line: body.slice(0, m.index).split("\n").length });
    }
    return found;
  }
  const pages = /(?:^|\/)pages\/(api(?:\/.*?))\.[cm]?[jt]sx?$/i.exec(file);
  return pages && !/\.(?:test|spec)$/i.test(pages[1]!) ? [{ method: "ANY", path: routePath(pages[1]!), file, line: 1 }] : [];
}

/** Bounded, read-only route literals from source files under projectDir. */
export function discoverSourceRoutes(projectDir: string, max = 120): SourceRouteHint[] {
  const out: SourceRouteHint[] = [];
  const seen = new Set<string>();
  let files = 0;
  const deadline = Date.now() + 1000;
  for (const full of walkFiles(projectDir, { skipDirs: new Set(["node_modules", ".git", ".crenel", "dist", "build", "coverage"]) })) {
    if (out.length >= max || Date.now() > deadline) break;
    if (!SOURCE.test(full)) continue;
    const rel = relative(projectDir, full).split("\\").join("/");
    if (NOISE_FILE.test(rel)) continue;
    if (++files > 5000) break;
    let body: string;
    try { if (statSync(full).size > 1024 * 1024) continue; body = readFileSync(full, "utf8"); } catch { continue; }
    if (body.slice(0, 8000).includes("\u0000")) continue;
    for (const route of conventionRoutes(rel, body)) {
      const key = `${route.method} ${route.path}`;
      if (!sanePath(route.path) || seen.has(key)) continue;
      seen.add(key);
      out.push(route);
      if (out.length >= max) return out;
    }
    for (const [i, raw] of body.split("\n").entries()) {
      const line = raw.slice(0, 2000);
      for (const p of PATTERNS) {
        const m = p.re.exec(line);
        if (!m || isCommentedAt(line, m.index)) continue;
        const path = p.path(m), method = p.method(m).toUpperCase();
        if (!sanePath(path)) continue;
        const key = `${method} ${path}`;
        if (seen.has(key) || (p.uniquePath && [...seen].some((v) => v.endsWith(` ${path}`)))) continue;
        seen.add(key);
        out.push({ method, path, file: rel, line: i + 1 });
        if (out.length >= max) return out;
      }
    }
  }
  return out;
}
