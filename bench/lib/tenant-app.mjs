// A tiny multi-tenant JSON API used by the live bench cases. No dependencies.
// Tokens map to users; every object has an owner tenant. Each route decides,
// on purpose, whether it checks ownership correctly.
import { createServer } from "node:http";

export const USERS = {
  "tok-a": { id: "user_a", tenant: "t_a", role: "member" },
  "tok-b": { id: "user_b", tenant: "t_b", role: "member" },
  "tok-c": { id: "user_c", tenant: "t_c", role: "member" },
};

export function userOf(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
  return m ? USERS[m[1]] ?? null : null;
}

export function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

// routes: [{ method, pattern: RegExp with one id group, handle(req, res, id) }]
export function serve(routes) {
  return createServer((req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    for (const r of routes) {
      const m = r.pattern.exec(path);
      if (m && (r.method ?? "GET") === req.method) return r.handle(req, res, decodeURIComponent(m[1] ?? ""));
    }
    json(res, 404, { error: "not found" });
  });
}
