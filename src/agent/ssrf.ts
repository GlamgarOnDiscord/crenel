// Out-of-band SSRF detection for the exploration layer (explore.ssrf).
//
// A server-side request forgery is blind by nature: the proof is not in the HTTP
// response, it is that the SERVER itself reached out to a destination the caller
// chose. So we prove it the industry-standard way (Burp Collaborator / interactsh):
// stand up an ephemeral listener on an address the target can reach, inject a
// callback URL carrying a unique nonce into the candidate parameter, and if the
// listener is hit with that nonce, the target performed the request — proven.
// Generic, definitive, no signature for any target. If nothing calls back within
// the window it stays a lead (a firewall, no egress, or simply not vulnerable).

import { createServer, type Server } from "node:http";
import { AddressInfo, isIP } from "node:net";

export interface Callback {
  /** The URL to inject; hitting it records the nonce. */
  url: (nonce: string) => string;
  /** Nonces seen by the listener (path or Host header carried them). */
  hits: () => string[];
  close: () => Promise<void>;
  port: number;
}

/**
 * Start an OOB listener. `host` is the address to advertise in callback URLs —
 * the one the TARGET can reach back (e.g. the host's docker bridge IP for a
 * container target, or a public collaborator for a remote target). The listener
 * binds that address when it is a local IP (loopback stays loopback), and all
 * interfaces only when it is a name or an address this machine does not hold
 * (a forwarded public collaborator). It records at most 5000 tokens.
 */
export async function startCallback(host: string, fixedPort = 0): Promise<Callback> {
  const seen: string[] = [];
  const srv: Server = createServer((req, res) => {
    try {
      const u = new URL(req.url ?? "/", "http://x");
      // nonce may ride any path segment (structured SSRF builds /a/b/<nonce>), the
      // query, or a subdomain label — record them all. Cap to bound memory.
      for (const seg of u.pathname.split("/")) if (seg && seen.length < 5000) seen.push(seg);
      const fromHost = (req.headers.host ?? "").split(":")[0] ?? "";
      for (const v of [u.searchParams.get("t") ?? "", fromHost, ...fromHost.split(".")]) if (v && seen.length < 5000) seen.push(v);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    } catch { try { res.writeHead(400); res.end(); } catch { /* socket gone */ } }
  });
  // A bad request line or an occupied fixed port must fail the validation cleanly,
  // never crash the process with an unhandled 'error'.
  const listen = (addr: string) => new Promise<number>((resolve, reject) => {
    srv.once("error", reject);
    srv.listen(fixedPort, addr, () => { srv.removeListener("error", reject); resolve((srv.address() as AddressInfo).port); });
  });
  let port: number;
  if (isIP(host)) {
    try { port = await listen(host); }
    catch (e) { if ((e as NodeJS.ErrnoException).code !== "EADDRNOTAVAIL") throw e; port = await listen("0.0.0.0"); }
  } else port = await listen("0.0.0.0");
  const authority = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host; // bracket IPv6 literals
  return {
    port,
    url: (nonce: string) => `http://${authority}:${port}/${nonce}`,
    hits: () => seen.slice(),
    close: () => new Promise<void>((r) => srv.close(() => r())),
  };
}

/** Proven iff the listener was hit with our nonce. Pure, testable. */
export function ssrfOracle(input: { nonce: string; hits: string[] }): { verdict: "proven" | "lead"; reason: string } {
  if (input.hits.includes(input.nonce)) return { verdict: "proven", reason: "the server made an outbound request to our listener (out-of-band callback received)" };
  return { verdict: "lead", reason: "no callback received: a firewall, no egress, or not vulnerable" };
}
