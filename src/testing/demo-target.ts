// Test fixture: an in-process vulnerable app on 127.0.0.1 (same behaviour as
// examples/vulnerable-app/server.mjs), recording every request it receives so
// tests can assert what was and was not sent. Never used outside tests.

import { createServer, type Server } from "node:http";

export interface DemoTarget {
  url: string;
  seen: { method: string; url: string; auth?: string }[];
  close(): Promise<void>;
  server: Server;
}

export const DEMO_TOKENS = { a: "tok-a", b: "tok-b", c: "tok-c" };

export function startDemoTarget(opts: { genericOk?: boolean; servesEnv?: boolean } = {}): Promise<DemoTarget> {
  const seen: DemoTarget["seen"] = [];
  const acct: Record<string, string> = { [DEMO_TOKENS.a]: "acct_a", [DEMO_TOKENS.b]: "acct_b", [DEMO_TOKENS.c]: "acct_c" };
  const projects: Record<string, { id: string; owner: string; name: string }> = {
    proj_b_1: { id: "proj_b_1", owner: "acct_b", name: "B roadmap" },
  };
  const server = createServer((req, res) => {
    seen.push({ method: req.method!, url: req.url!, auth: req.headers.authorization });
    const who = acct[(req.headers.authorization ?? "").replace(/^Bearer\s+/i, "")];
    const p = new URL(req.url!, "http://x").pathname;
    const json = (s: number, b: unknown) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
    if (p === "/") { res.writeHead(200, { "content-type": "text/html" }); res.end("<h1>demo</h1>"); return; }
    if (p === "/.env" && opts.servesEnv) { res.writeHead(200, { "content-type": "text/plain" }); res.end("DATABASE_URL=postgres://app@db/app\n"); return; }
    let m = p.match(/^\/api\/projects\/([^/]+)$/);
    if (m) {
      if (!who) return json(401, {});
      if (opts.genericOk) return json(200, { ok: true }); // answers everything the same way
      const pr = projects[decodeURIComponent(m[1]!)];
      return pr ? json(200, pr) : json(404, {});
    }
    m = p.match(/^\/api\/renders\/([^/]+)$/);
    if (m) return who === "acct_b" ? json(200, { id: m[1], owner: "acct_b" }) : json(who ? 404 : 401, {});
    json(404, {});
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => {
    const port = (server.address() as { port: number }).port;
    ok({ url: `http://127.0.0.1:${port}`, seen, server, close: () => new Promise((d) => { server.closeAllConnections(); server.close(() => d()); }) });
  }));
}
