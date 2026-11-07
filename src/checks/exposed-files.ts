// exposed-files: files a web server should never hand out, requested on the
// declared staging URL the way nuclei's exposure templates do: /.env, /.git/,
// database dumps, backups, debug endpoints. A short list of paths that matter on
// a SaaS, each with a content signature, so the proof is the file itself and not
// a status code: a soft 404 (every path answers 200 with the SPA's index.html)
// is caught by a negative control on a random path, and a 200 without the
// signature is ignored. GET only, declared host only, a handful of requests.

import { randomBytes } from "node:crypto";
import type { Check, CheckContext, Finding, Severity } from "../core/types.js";
import { safeFetch } from "../core/net.js";

interface Probe {
  path: string;
  what: string;
  severity: Severity;
  /** The body must match this to count: the file's own shape, not a page. */
  signature: RegExp;
  remediation: string;
}

const PROBES: Probe[] = [
  { path: "/.env", what: "environment file with secrets", severity: "critical", signature: /^\s*(#.*\n\s*)*[A-Z][A-Z0-9_]{2,}\s*=\s*\S/m,
    remediation: "Remove the file from the web root, rotate every secret it holds, and block dotfiles at the edge." },
  { path: "/.env.production", what: "production environment file", severity: "critical", signature: /^\s*(#.*\n\s*)*[A-Z][A-Z0-9_]{2,}\s*=\s*\S/m,
    remediation: "Remove it from the web root, rotate every secret it holds, and block dotfiles at the edge." },
  { path: "/.git/config", what: "Git repository metadata (the source can be rebuilt from /.git/)", severity: "high", signature: /\[core\][\s\S]*repositoryformatversion/,
    remediation: "Do not deploy the .git directory; block /.git/ at the edge. Treat the source and its history as public." },
  { path: "/.git/HEAD", what: "Git repository metadata", severity: "high", signature: /^ref: refs\/heads\/[\w./-]+\s*$/,
    remediation: "Do not deploy the .git directory; block /.git/ at the edge." },
  { path: "/backup.sql", what: "database dump", severity: "critical", signature: /(CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump)/i,
    remediation: "Remove the dump, rotate database credentials, and check access logs for downloads." },
  { path: "/dump.sql", what: "database dump", severity: "critical", signature: /(CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump)/i,
    remediation: "Remove the dump, rotate database credentials, and check access logs for downloads." },
  { path: "/.DS_Store", what: "macOS folder index (lists files in the directory)", severity: "low", signature: /^\0\0\0\x01Bud1/,
    remediation: "Remove .DS_Store files from the deploy and block them at the edge." },
  { path: "/server-status", what: "Apache server-status page (live requests and client IPs)", severity: "medium", signature: /Apache Server Status for/i,
    remediation: "Restrict mod_status to localhost." },
  { path: "/actuator/env", what: "Spring Boot actuator environment (config and secrets)", severity: "critical", signature: /"(activeProfiles|propertySources)"\s*:/,
    remediation: "Do not expose actuator endpoints publicly; require auth and limit them to health." },
  { path: "/.vscode/sftp.json", what: "editor deploy config with server credentials", severity: "high", signature: /"(host|password|privateKeyPath)"\s*:/,
    remediation: "Remove editor folders from the deploy and rotate the server credentials." },
  { path: "/phpinfo.php", what: "phpinfo page (full server config)", severity: "medium", signature: /<title>phpinfo\(\)<\/title>|PHP Version \d/i,
    remediation: "Delete the page." },
];

export const exposedFiles: Check = {
  name: "exposed-files",
  title: "Sensitive files served by the deployed site (.env, .git, dumps, debug pages)",
  readOnly: true, // a few GETs on the declared host, like a crawler
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) {
      ctx.log("exposed-files: no stagingUrl declared, nothing to request");
      return [];
    }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    // Negative control: what does a path that cannot exist return?
    let control = "";
    try {
      const c = await safeFetch(`${base}/crenel-nonexistent-${randomBytes(6).toString("hex")}`, ctx.scope);
      if (c.status === 200) control = c.body;
    } catch { /* unreachable host: every probe below will say so */ }

    const findings: Finding[] = [];
    for (const p of PROBES) {
      const url = base + p.path;
      let res;
      try { res = await safeFetch(url, ctx.scope); } catch (err) { ctx.log(`exposed-files: ${url}: ${(err as Error).message}`); continue; }
      if (res.status !== 200) continue;
      if (control && res.body === control) continue; // the app answers everything with the same page
      if (!p.signature.test(res.body)) continue;
      findings.push({
        id: `exposed-files:${p.path}`,
        check: "exposed-files",
        title: `${p.path} is served publicly (${p.what})`,
        severity: p.severity,
        state: "proven",
        location: url,
        description: `GET ${url} returned 200 with content that matches a ${p.what}, and a random path does not return the same thing. Anyone can download it.`,
        remediation: p.remediation,
        proof: { method: "GET on the declared host, content signature checked, negative control on a random path", replay: `curl -s '${url}' | head -5`, evidence: `HTTP 200, ${res.body.length} bytes, signature matched (content not kept)` },
        regressionHint: `After deploy, expect ${p.path} to return 403 or 404.`,
      });
    }
    ctx.log(`exposed-files: ${PROBES.length} path(s) requested, ${findings.length} exposed`);
    return findings;
  },
};
