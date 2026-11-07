// email-dns: can anyone send mail as your domain? A SaaS sends password resets
// and invoices; without SPF and an enforcing DMARC policy, a phishing mail can
// carry your exact From address and land in the inbox. Pure DNS: the TXT
// records of the domain and of _dmarc.<domain>. Nothing is sent to your hosts.

import { promises as dns } from "node:dns";
import type { Check, CheckContext, Finding, Severity } from "../core/types.js";

export type TxtResolver = (name: string) => Promise<string[][]>;
const systemTxt: TxtResolver = (n) => dns.resolveTxt(n);

/** The mail domain: options.email-dns.domain, else the staging host minus a leading staging/app label. */
function mailDomain(ctx: CheckContext): string | null {
  const opt = ((ctx.options["email-dns"] ?? {}) as { domain?: string }).domain;
  if (opt) return opt.toLowerCase();
  if (!ctx.stagingUrl) return null;
  const host = new URL(ctx.stagingUrl).hostname.toLowerCase();
  if (/^[\d.:]+$/.test(host) || host === "localhost") return null;
  const labels = host.split(".");
  return labels.length > 2 && /^(www|app|staging|stage|preview|dev|api|dashboard)$/.test(labels[0]!) ? labels.slice(1).join(".") : host;
}

export function makeEmailDns(resolveTxt: TxtResolver = systemTxt): Check {
  return {
    name: "email-dns",
    title: "Mail spoofing: SPF and DMARC of your domain",
    readOnly: true, // DNS TXT lookups only
    async run(ctx: CheckContext): Promise<Finding[]> {
      const domain = mailDomain(ctx);
      if (!domain) return [];
      const txt = async (name: string) => { try { return (await resolveTxt(name)).map((r) => r.join("")); } catch { return []; } };
      const spf = (await txt(domain)).filter((r) => /^v=spf1\b/i.test(r));
      const dmarc = (await txt(`_dmarc.${domain}`)).filter((r) => /^v=DMARC1\b/i.test(r));
      const out: Finding[] = [];
      const push = (id: string, title: string, severity: Severity, description: string, remediation: string, evidence: string, replay: string) =>
        out.push({ id: `email-dns:${id}:${domain}`, check: "email-dns", title, severity, state: "proven", location: domain, description, remediation, proof: { method: "DNS TXT lookup", replay, evidence } });

      if (!spf.length) push("no-spf", `No SPF record on ${domain}`, "medium", `${domain} publishes no SPF record, so receivers cannot tell which servers may send its mail.`, `Publish one TXT record "v=spf1 include:<your mail provider> -all".`, "no v=spf1 TXT record", `dig +short TXT ${domain}`);
      else if (/\s\+all\b/i.test(spf[0]!) || /\s\?all\b/i.test(spf[0]!)) push("spf-open", `SPF on ${domain} lets any server send (${/\+all/i.test(spf[0]!) ? "+all" : "?all"})`, "high", `The SPF record ends with ${/\+all/i.test(spf[0]!) ? "+all" : "?all"}: every server on the internet is allowed to send as ${domain}.`, "End the SPF record with -all (or ~all while you migrate).", spf[0]!, `dig +short TXT ${domain}`);
      if (spf.length > 1) push("spf-multiple", `${spf.length} SPF records on ${domain} (SPF fails when there is more than one)`, "medium", `Receivers treat several v=spf1 records as a permanent error, so SPF protects nothing.`, "Merge them into a single v=spf1 record.", spf.join(" | "), `dig +short TXT ${domain}`);

      if (!dmarc.length) push("no-dmarc", `No DMARC record on ${domain}: mail can be spoofed with your exact From address`, "medium", `_dmarc.${domain} has no DMARC policy. Without it, a forged mail with From: ...@${domain} is not rejected, even when SPF and DKIM fail.`, `Publish "v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}" at _dmarc.${domain}, then move to p=reject.`, "no v=DMARC1 TXT record", `dig +short TXT _dmarc.${domain}`);
      else {
        const p = /\bp\s*=\s*(\w+)/i.exec(dmarc[0]!)?.[1]?.toLowerCase();
        if (p === "none") push("dmarc-none", `DMARC on ${domain} only monitors (p=none): spoofed mail is still delivered`, "low", `The DMARC policy is p=none: receivers report forged mail but deliver it.`, "Move to p=quarantine, then p=reject, once your reports show only your own senders.", dmarc[0]!, `dig +short TXT _dmarc.${domain}`);
      }
      ctx.log(`email-dns: ${domain}, ${out.length} finding(s)`);
      return out;
    },
  };
}

export const emailDns = makeEmailDns();
