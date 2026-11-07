// Scoped egress proxy: the only network exit of an external tool.
//
// net.ts guards every request Crenel itself sends. An external tool (nuclei,
// katana, trufflehog) has its own HTTP client, so it would bypass net.ts. The
// toolbox therefore runs those tools in a container with no route out, whose
// only exit is this proxy, started by Crenel for the duration of one run. The
// proxy applies the same rules as net.ts:
//
//   1. the host must be in the Scope allowlist;
//   2. the host is resolved HERE, every address is checked (no private,
//      loopback, link-local or metadata address unless scope.allowPrivate), and
//      the connection goes to the address that was checked (pinned: a second
//      DNS answer cannot rebind it);
//   3. plain HTTP: only GET, HEAD and OPTIONS are forwarded. Redirects are not
//      followed by the proxy: the tool follows them with a new request, which
//      is checked again from step 1 (an off-scope Location is also journalled);
//   4. HTTPS (CONNECT): the proxy does NOT decrypt. It checks the host, the
//      port (443 or 80 only) and the resolved address, then relays bytes. The
//      METHOD inside the tunnel is invisible to it, so it cannot be filtered:
//      that is why only non-intrusive tool modes are allowed (filtered nuclei
//      templates, katana without form filling, trufflehog without verification
//      by default). See docs/TOOLBOX.md;
//   5. a request budget, a rate limit, a response size cap, timeouts, and the
//      scope's kill switch;
//   6. every request and every refusal is reported to `onEvent` (the audit
//      JSONL) and to scope.onRequest (the run journal and its monitor).
//
// The proxy asks for a per-run credential (Proxy-Authorization) so another
// local process cannot borrow it. Dependency-free, like net.ts.

import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse, type IncomingHttpHeaders } from "node:http";
import { connect, isIP, type Socket, type AddressInfo } from "node:net";
import { lookup } from "node:dns/promises";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { isPrivateIp } from "./net.js";
import type { Scope } from "./scope.js";

export const PROXY_SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
export const CONNECT_PORTS = new Set([443, 80]);

export interface ProxyEvent {
  at: string;
  kind: "egress";
  /** "http" for a forwarded plain-HTTP request, "connect" for an HTTPS tunnel. */
  via: "http" | "connect";
  method: string;
  /** Full URL for http, host:port for connect. */
  target: string;
  /** The address actually dialled (pinned after the check). */
  ip?: string;
  status?: number;
  bytes?: number;
  refused?: string;
  error?: string;
  /** Set when a response redirects outside the declared hosts. */
  offScopeRedirect?: string;
  tool?: string;
}

export interface EgressProxyOptions {
  scope: Scope;
  /** Address to listen on. Default 127.0.0.1. */
  host?: string;
  /** Port, 0 for a random one (default). */
  port?: number;
  /** Listen on this Unix socket instead of host:port (the toolbox relay on Linux). */
  socketPath?: string;
  /** Credential required in Proxy-Authorization (Basic, any user). Random when omitted. */
  token?: string;
  /** Requests per second across the run (default 10). Extra requests wait their turn. */
  ratePerSec?: number;
  /** Total requests and tunnels allowed (default 2000). Over it, everything is refused. */
  maxRequests?: number;
  /** Cap on a plain-HTTP response body, in bytes (default 2 MB, as net.ts). */
  maxResponseBytes?: number;
  /** Cap on the bytes relayed through one tunnel (default 20 MB). */
  maxTunnelBytes?: number;
  /** Ports a CONNECT may reach (default 443 and 80). Tests use a local port. */
  connectPorts?: number[];
  /** Upstream timeout in ms (default 15 s, as net.ts). */
  timeoutMs?: number;
  /** Label written on every event (e.g. "nuclei"). */
  tool?: string;
  onEvent?: (e: ProxyEvent) => void;
  /** DNS resolver, injectable for tests. */
  resolve?: (host: string) => Promise<string[]>;
}

export interface EgressProxy {
  /** host:port the proxy listens on (port 0 and host = socket path when on a Unix socket). */
  host: string;
  port: number;
  socketPath?: string;
  token: string;
  /** http://crenel:<token>@host:port, for HTTP(S)_PROXY. */
  url: string;
  stats: { requests: number; refused: number };
  close(): Promise<void>;
}

class Refusal extends Error {}

const HOP_BY_HOP = ["connection", "proxy-connection", "keep-alive", "proxy-authorization", "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade"];

async function defaultResolve(host: string): Promise<string[]> {
  const addrs = await lookup(host, { all: true, verbatim: true });
  return addrs.map((a) => a.address);
}

/** Start the proxy. Resolves once it listens. */
export async function startEgressProxy(opts: EgressProxyOptions): Promise<EgressProxy> {
  const scope = opts.scope;
  const token = opts.token ?? randomBytes(18).toString("base64url");
  const ratePerSec = opts.ratePerSec ?? 10;
  const maxRequests = opts.maxRequests ?? 2000;
  const maxResponseBytes = opts.maxResponseBytes ?? 2 * 1024 * 1024;
  const maxTunnelBytes = opts.maxTunnelBytes ?? 20 * 1024 * 1024;
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const resolve = opts.resolve ?? defaultResolve;
  const connectPorts = new Set(opts.connectPorts ?? [...CONNECT_PORTS]);
  const stats = { requests: 0, refused: 0 };
  const sockets = new Set<Socket>();

  const emit = (e: Omit<ProxyEvent, "at" | "kind" | "tool">) => {
    const ev: ProxyEvent = { at: new Date().toISOString(), kind: "egress", ...e, ...(opts.tool ? { tool: opts.tool } : {}) };
    if (ev.refused) stats.refused++;
    try { opts.onEvent?.(ev); } catch { /* an observer never breaks the proxy */ }
    const url = ev.via === "connect" ? `https://${ev.target}/` : ev.target;
    try {
      scope.onRequest?.({ method: ev.method, url, ...(ev.refused ? { refused: ev.refused } : {}), ...(ev.status !== undefined ? { status: ev.status } : {}), ...(ev.error ? { error: ev.error } : {}) });
    } catch { /* idem */ }
  };

  // Rate limit: one slot every 1000/rate ms, shared by the run.
  let nextSlot = 0;
  const waitTurn = async () => {
    const now = Date.now();
    const slot = Math.max(now, nextSlot);
    nextSlot = slot + Math.ceil(1000 / Math.max(ratePerSec, 0.1));
    if (slot > now) await new Promise((r) => setTimeout(r, slot - now));
  };

  const authorized = (headers: IncomingHttpHeaders): boolean => {
    const h = headers["proxy-authorization"];
    if (typeof h !== "string") return false;
    const m = h.match(/^Basic\s+(.+)$/i);
    if (!m) return false;
    const decoded = Buffer.from(m[1]!, "base64").toString("utf8");
    const pass = decoded.slice(decoded.indexOf(":") + 1);
    const a = Buffer.from(pass), b = Buffer.from(token);
    return a.length === b.length && timingSafeEqual(a, b);
  };

  /** Steps 1 and 2: scope, resolution, address check. Returns the pinned address. */
  const check = async (hostname: string): Promise<string> => {
    if (scope.signal?.aborted) throw new Refusal("run stopped (kill switch)");
    if (stats.requests >= maxRequests) throw new Refusal(`request budget exhausted (${maxRequests})`);
    const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (!scope.isHostAllowed(`http://${isIP(host) === 6 ? `[${host}]` : host}/`)) throw new Refusal(`${host} is not in allowedHosts`);
    let addrs: string[];
    if (isIP(host)) addrs = [host];
    else {
      try { addrs = await resolve(host); } catch { throw new Refusal(`cannot resolve ${host}`); }
      if (addrs.length === 0) throw new Refusal(`cannot resolve ${host}`);
    }
    if (!scope.allowPrivate) {
      const bad = addrs.find((a) => isPrivateIp(a));
      if (bad) throw new Refusal(`${host} resolves to a private address (${bad})`);
    }
    stats.requests++;
    return addrs[0]!;
  };

  const deny = (res: ServerResponse, status: number, msg: string) => {
    if (res.headersSent) { res.destroy(); return; }
    res.writeHead(status, { "content-type": "text/plain", "x-crenel-proxy": "refused", connection: "close" });
    res.end(`crenel egress proxy: ${msg}\n`);
  };

  // ---- plain HTTP (absolute-form requests) ----
  const onRequest = async (req: IncomingMessage, res: ServerResponse) => {
    const method = (req.method ?? "GET").toUpperCase();
    const raw = req.url ?? "";
    if (!authorized(req.headers)) {
      emit({ via: "http", method, target: raw, refused: "missing or wrong proxy credential" });
      res.writeHead(407, { "proxy-authenticate": 'Basic realm="crenel"', connection: "close" });
      return res.end();
    }
    let url: URL;
    try { url = new URL(raw); } catch {
      emit({ via: "http", method, target: raw, refused: "not an absolute http URL" });
      return deny(res, 400, "absolute http:// URL expected");
    }
    if (url.protocol !== "http:") {
      emit({ via: "http", method, target: raw, refused: `${url.protocol} over plain proxy` });
      return deny(res, 400, "only http:// is forwarded; use CONNECT for https");
    }
    if (!PROXY_SAFE_METHODS.has(method)) {
      emit({ via: "http", method, target: url.toString(), refused: `${method}: only GET, HEAD and OPTIONS are forwarded` });
      return deny(res, 405, `${method} refused, read-only methods only`);
    }
    let ip: string;
    try { ip = await check(url.hostname); } catch (err) {
      const msg = err instanceof Refusal ? err.message : (err as Error).message;
      emit({ via: "http", method, target: url.toString(), refused: msg });
      return deny(res, 403, msg);
    }
    await waitTurn();
    const headers: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(req.headers)) if (v !== undefined && !HOP_BY_HOP.includes(k)) headers[k] = v;
    headers.host = url.host;
    headers.connection = "close";
    const port = Number(url.port || 80);
    const up = httpRequest({ host: ip, port, method, path: url.pathname + url.search, headers, timeout: timeoutMs, signal: scope.signal });
    let bytes = 0;
    up.on("response", (ur) => {
      const loc = ur.headers.location;
      let offScopeRedirect: string | undefined;
      if (loc && ur.statusCode && ur.statusCode >= 300 && ur.statusCode < 400) {
        try { const next = new URL(loc, url); if (!scope.isHostAllowed(next.toString())) offScopeRedirect = next.toString(); } catch { /* ignore */ }
      }
      const out: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(ur.headers)) if (v !== undefined && !HOP_BY_HOP.includes(k)) out[k] = v;
      out.connection = "close";
      res.writeHead(ur.statusCode ?? 502, out);
      let truncated = false;
      ur.on("data", (chunk: Buffer) => {
        if (truncated) return;
        if (bytes + chunk.length > maxResponseBytes) {
          res.write(chunk.subarray(0, maxResponseBytes - bytes));
          bytes = maxResponseBytes;
          truncated = true;
          ur.destroy();
          res.end();
          return;
        }
        bytes += chunk.length;
        res.write(chunk);
      });
      ur.on("end", () => res.end());
      ur.on("close", () => {
        emit({ via: "http", method, target: url.toString(), ip, status: ur.statusCode, bytes, ...(offScopeRedirect ? { offScopeRedirect } : {}), ...(truncated ? { error: `response capped at ${maxResponseBytes} bytes` } : {}) });
      });
    });
    up.on("timeout", () => up.destroy(new Error(`upstream timeout after ${timeoutMs} ms`)));
    up.on("error", (err) => {
      emit({ via: "http", method, target: url.toString(), ip, error: err.message });
      if (!res.headersSent) deny(res, 502, `upstream error: ${err.message}`);
      else res.destroy();
    });
    req.pipe(up);
  };

  // ---- HTTPS tunnels ----
  const onConnect = async (req: IncomingMessage, client: Socket, head: Buffer) => {
    const target = req.url ?? "";
    const fail = (status: number, text: string, refused: string) => {
      emit({ via: "connect", method: "CONNECT", target, refused });
      client.end(`HTTP/1.1 ${status} ${text}\r\nx-crenel-proxy: refused\r\nconnection: close\r\n\r\n`);
    };
    client.on("error", () => {});
    if (!authorized(req.headers)) {
      emit({ via: "connect", method: "CONNECT", target, refused: "missing or wrong proxy credential" });
      return client.end('HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic realm="crenel"\r\n\r\n');
    }
    const m = target.match(/^(\[[^\]]+\]|[^:]+):(\d+)$/);
    if (!m) return fail(400, "Bad Request", "CONNECT target must be host:port");
    const host = m[1]!, port = Number(m[2]);
    if (!connectPorts.has(port)) return fail(403, "Forbidden", `CONNECT to port ${port}: only ${[...connectPorts].join(" and ")} are tunnelled`);
    let ip: string;
    try { ip = await check(host); } catch (err) {
      return fail(403, "Forbidden", err instanceof Refusal ? err.message : (err as Error).message);
    }
    await waitTurn();
    const up = connect({ host: ip, port });
    sockets.add(up);
    let bytes = 0;
    let done = false;
    const finish = (error?: string) => {
      if (done) return;
      done = true;
      emit({ via: "connect", method: "CONNECT", target, ip, bytes, ...(error ? { error } : { status: 200 }) });
      up.destroy();
      client.destroy();
    };
    up.setTimeout(timeoutMs, () => finish(`idle tunnel closed after ${timeoutMs} ms`));
    client.setTimeout(timeoutMs, () => finish(`idle tunnel closed after ${timeoutMs} ms`));
    up.on("connect", () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) up.write(head);
      client.pipe(up);
    });
    up.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maxTunnelBytes) return finish(`tunnel capped at ${maxTunnelBytes} bytes`);
      client.write(chunk);
    });
    up.on("end", () => finish());
    up.on("error", (err) => {
      if (!client.writableEnded && bytes === 0) client.write(`HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n`);
      finish(err.message);
    });
    client.on("close", () => finish());
    scope.signal?.addEventListener("abort", () => finish("run stopped (kill switch)"), { once: true });
  };

  const server = createServer((req, res) => { void onRequest(req, res); });
  server.on("connect", (req, socket, head) => { void onConnect(req, socket as Socket, head); });
  server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  // Absolute-form requests only: an origin-form request (a client that thinks
  // the proxy is the web server) has no host to check and is refused above.

  const listenHost = opts.socketPath ?? opts.host ?? "127.0.0.1";
  await new Promise<void>((ok, ko) => {
    server.once("error", ko);
    if (opts.socketPath) server.listen(opts.socketPath, () => ok());
    else server.listen(opts.port ?? 0, listenHost, () => ok());
  });
  const port = opts.socketPath ? 0 : (server.address() as AddressInfo).port;
  const shown = isIP(listenHost) === 6 ? `[${listenHost}]` : listenHost;
  return {
    host: listenHost, port, token, stats, ...(opts.socketPath ? { socketPath: opts.socketPath } : {}),
    url: `http://crenel:${token}@${shown}:${port}`,
    close: () => new Promise<void>((ok) => {
      for (const s of sockets) s.destroy();
      server.close(() => ok());
    }),
  };
}
