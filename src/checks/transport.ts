// transport: is the site only reachable over HTTPS, and is its certificate
// about to expire? Plain HTTP that serves the app instead of redirecting lets a
// network attacker read and change pages and cookies; an expiring certificate
// is an outage waiting. One GET over http:// (redirect read, not followed) and
// one TLS handshake to the declared host.

import { connect } from "node:tls";
import { lookup } from "node:dns/promises";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch, isPrivateIp } from "../core/net.js";

const DAY = 86_400_000;

/** Days until the certificate of host:443 expires, through a guarded TLS handshake. */
async function certDaysLeft(host: string, allowPrivate: boolean, now = Date.now()): Promise<{ days: number; validTo: string } | null> {
  const { address } = await lookup(host);
  if (!allowPrivate && isPrivateIp(address)) return null;
  return new Promise((resolve) => {
    const socket = connect({ host: address, port: 443, servername: host, rejectUnauthorized: false, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert?.valid_to) return resolve(null);
      resolve({ days: Math.floor((Date.parse(cert.valid_to) - now) / DAY), validTo: cert.valid_to });
    });
    socket.on("error", () => resolve(null));
    socket.on("timeout", () => { socket.destroy(); resolve(null); });
  });
}

export const transport: Check = {
  name: "transport",
  title: "HTTPS only, and a certificate that is not about to expire",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const u = new URL(ctx.stagingUrl);
    if (u.protocol !== "https:" || !ctx.scope.isHostAllowed(ctx.stagingUrl)) return [];
    const out: Finding[] = [];
    try {
      const plain = await safeFetch(`http://${u.host}${u.pathname}`, ctx.scope, { followRedirects: false });
      const loc = plain.headers.get("location") ?? "";
      if (plain.status === 200) {
        out.push({
          id: `transport:http-served:${u.host}`, check: "transport", title: `${u.host} serves the app over plain HTTP instead of redirecting`, severity: "medium", state: "proven",
          location: `http://${u.host}${u.pathname}`,
          description: `GET http://${u.host}${u.pathname} answers 200: the page is served unencrypted, so anyone on the network can read or change it and steal cookies without the Secure flag.`,
          remediation: "Redirect every http:// request to https:// with a 301 or 308, and set HSTS.",
          proof: { method: "GET over http://, redirect not followed", replay: `curl -sI http://${u.host}${u.pathname} | head -3`, evidence: "HTTP 200 over http://" },
          regressionHint: `http://${u.host}/ must redirect to https://.`,
        });
      } else if (plain.status >= 300 && plain.status < 400 && loc && !loc.startsWith("https://")) {
        ctx.log(`transport: http:// redirects to ${loc}, not to https://`);
      }
    } catch (err) { ctx.log(`transport: http:// ${(err as Error).message}`); }
    try {
      const c = await certDaysLeft(u.hostname, ctx.scope.allowPrivate);
      if (c && c.days < 21) {
        out.push({
          id: `transport:cert-expiry:${u.hostname}`, check: "transport",
          title: c.days < 0 ? `TLS certificate of ${u.hostname} expired ${-c.days} day(s) ago` : `TLS certificate of ${u.hostname} expires in ${c.days} day(s)`,
          severity: c.days < 7 ? "high" : "medium", state: "proven", location: `${u.hostname}:443`,
          description: `The certificate served on ${u.hostname} is valid until ${c.validTo}. When it lapses, browsers block the site and API clients fail.`,
          remediation: "Renew it now and make renewal automatic (ACME), with an alert well before expiry.",
          proof: { method: "TLS handshake, peer certificate read", replay: `echo | openssl s_client -connect ${u.hostname}:443 -servername ${u.hostname} 2>/dev/null | openssl x509 -noout -enddate`, evidence: `notAfter ${c.validTo}` },
        });
      }
    } catch (err) { ctx.log(`transport: TLS ${(err as Error).message}`); }
    return out;
  },
};
