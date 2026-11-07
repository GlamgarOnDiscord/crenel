// subdomain-takeover: a declared host whose CNAME points at a hosting service
// (Heroku, Vercel, Netlify, GitHub Pages, S3, Azure, Shopify, Fastly…) where
// the app or bucket no longer exists. Anyone can claim that name on the service
// and serve their page on your subdomain, with your cookies in scope. The method
// of can-i-take-over-xyz and nuclei's takeover templates: a CNAME to a known
// service, and that service's own "nothing here" page as the answer. DNS
// lookups and one GET per declared host; nothing is ever claimed.

import { promises as dns } from "node:dns";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";

interface Service { name: string; cname: RegExp; fingerprint: RegExp }

export const SERVICES: Service[] = [
  { name: "Heroku", cname: /\.herokuapp\.com\.?$|\.herokudns\.com\.?$/i, fingerprint: /No such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { name: "GitHub Pages", cname: /\.github\.io\.?$/i, fingerprint: /There isn't a GitHub Pages site here/i },
  { name: "Netlify", cname: /\.netlify\.(app|com)\.?$/i, fingerprint: /Not Found - Request ID|netlify.*page not found/i },
  { name: "Vercel", cname: /\.vercel(-dns)?\.(app|com)\.?$|cname\.vercel-dns\.com\.?$/i, fingerprint: /DEPLOYMENT_NOT_FOUND|The deployment could not be found/i },
  { name: "AWS S3", cname: /\.s3[.-][\w.-]*amazonaws\.com\.?$|\.s3\.amazonaws\.com\.?$/i, fingerprint: /NoSuchBucket|The specified bucket does not exist/i },
  { name: "Azure", cname: /\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net)\.?$/i, fingerprint: /404 Web Site not found|Error 404 - Web app not found|The specified container does not exist/i },
  { name: "Shopify", cname: /\.myshopify\.com\.?$|shops\.myshopify\.com\.?$/i, fingerprint: /Sorry, this shop is currently unavailable|Only one step left/i },
  { name: "Fastly", cname: /\.fastly\.net\.?$/i, fingerprint: /Fastly error: unknown domain/i },
  { name: "Render", cname: /\.onrender\.com\.?$/i, fingerprint: /Not Found|no-deploy/i },
  { name: "Fly.io", cname: /\.fly\.dev\.?$/i, fingerprint: /404 Not Found|not found/i },
];

export type CnameResolver = (host: string) => Promise<string[]>;
const systemResolver: CnameResolver = (h) => dns.resolveCname(h);

export type BodyFetcher = (url: string, ctx: CheckContext) => Promise<{ status: number; body: string }>;
const scopedFetch: BodyFetcher = (url, ctx) => safeFetch(url, ctx.scope);

export function makeSubdomainTakeover(resolveCname: CnameResolver = systemResolver, fetchBody: BodyFetcher = scopedFetch): Check {
  return {
    name: "subdomain-takeover",
    title: "Subdomain pointing at a hosting service where nothing is deployed (takeover)",
    readOnly: true, // DNS lookups and one GET per declared host
    async run(ctx: CheckContext): Promise<Finding[]> {
      const hosts = [...new Set(ctx.scope.allowedHosts.filter((h) => /[a-z]/i.test(h) && !h.includes("*")))];
      const findings: Finding[] = [];
      for (const host of hosts) {
        let cnames: string[] = [];
        try { cnames = await resolveCname(host); } catch { continue; } // no CNAME: nothing to take over
        for (const target of cnames) {
          const svc = SERVICES.find((s) => s.cname.test(target));
          if (!svc) continue;
          let res;
          try { res = await fetchBody(`https://${host}/`, ctx); } catch {
            try { res = await fetchBody(`http://${host}/`, ctx); } catch { continue; }
          }
          if (!svc.fingerprint.test(res.body)) continue;
          findings.push({
            id: `subdomain-takeover:${host}`,
            check: "subdomain-takeover",
            title: `${host} points at ${svc.name} (${target}) where nothing is deployed: takeover possible`,
            severity: "high",
            state: "proven",
            location: host,
            description: `${host} has a CNAME to ${target}, and ${svc.name} answers with its "nothing here" page. Anyone can create that app or bucket on ${svc.name} and serve their own content on ${host}, reading cookies scoped to your domain.`,
            remediation: `Delete the DNS record for ${host}, or claim ${target} again on ${svc.name}. Remove DNS records when you delete a deployment.`,
            proof: { method: "CNAME to a known hosting service, and that service's own not-found page", replay: `dig +short CNAME ${host}; curl -s https://${host}/ | head -20`, evidence: `CNAME ${target}; HTTP ${res.status}, ${svc.name} not-found page` },
            regressionHint: `${host} must not resolve to an unclaimed ${svc.name} name.`,
          });
          break;
        }
      }
      ctx.log(`subdomain-takeover: ${hosts.length} host(s) checked, ${findings.length} finding(s)`);
      return findings;
    },
  };
}

export const subdomainTakeover = makeSubdomainTakeover();
