// dependency-risk: catch the supply-chain mistakes that hit real SaaS, offline
// and deterministically. Three signals, no network needed:
//
//   1. A locked package whose exact name@version is on a denylist of versions
//      known to have shipped malware (the @tanstack/* incident is the seed).
//      A match is PROVEN critical: assume compromise and pin away from it.
//   2. The project's own install scripts (preinstall/postinstall/prepare) that
//      run arbitrary code on `install`. A lead, since CI should pass
//      --ignore-scripts and the author should know what runs.
//   3. Dependencies pulled from outside the registry (git/http/file:), which
//      bypass the registry's integrity and 2FA. A lead.
//   4. No lockfile at all: installs are not reproducible. A lead.
//
// Online enrichment (OSV for known CVEs) is deliberately left out of the
// default run so the check stays deterministic and free; it belongs behind an
// explicit flag.

import { relative } from "../core/walk.js";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
// Bundled at build time, so the denylist always ships with the check.
import denylistData from "../data/known-bad-packages.json" with { type: "json" };

interface KnownBad {
  name: string;
  version: string;
  advisory: string;
  note: string;
}

function loadDenylist(): KnownBad[] {
  return ((denylistData as { packages?: KnownBad[] }).packages ?? []);
}

// Walk up from the scanned dir to the nearest package root, so pointing Crenel
// at a built bundle still finds the manifest above it.
function findPackageRoot(start: string): string | null {
  let dir = start;
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, "package.json"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

const LOCKFILES = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lock", "bun.lockb"];

// Pull every name@version pair out of a lockfile, tolerant of pnpm/npm/yarn
// shapes. We only need the pairs, not the full dependency graph.
export function parseLockedVersions(text: string): Set<string> {
  const out = new Set<string>();
  // pnpm v9: keys like '@scope/name@1.2.3(peer)' or name@1.2.3:
  const pnpm = /(?:^|\n)\s{2,}'?((?:@[^@\s/'"]+\/)?[^@\s/'":]+)@([0-9][^\s'":()]*)/g;
  let m: RegExpExecArray | null;
  while ((m = pnpm.exec(text)) !== null) out.add(`${m[1]}@${m[2]}`);
  // npm v3 lockfile: "node_modules/name": { "version": "1.2.3" }
  const npm = /"node_modules\/((?:@[^"]+\/)?[^"]+)":\s*\{[^}]*?"version":\s*"([^"]+)"/g;
  while ((m = npm.exec(text)) !== null) out.add(`${m[1]}@${m[2]}`);
  return out;
}

export const dependencyRisk: Check = {
  name: "dependency-risk",
  title: "Supply-chain risk in dependencies (malware, install scripts, non-registry)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const root = findPackageRoot(ctx.projectDir);
    if (!root) {
      ctx.log("dependency-risk: no package.json found above the scanned directory");
      return findings;
    }
    const rel = (p: string) => relative(ctx.projectDir, p) || p;

    // --- package.json: install scripts and non-registry deps ---
    let pkg: Record<string, unknown> = {};
    const pkgPath = join(root, "package.json");
    try {
      pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    } catch {
      ctx.log("dependency-risk: package.json unreadable");
    }

    const scripts = (pkg.scripts ?? {}) as Record<string, string>;
    for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
      if (scripts[hook]) {
        findings.push({
          id: `dependency-risk:install-script:${hook}`,
          check: "dependency-risk",
          title: `Install hook "${hook}" runs on every install`,
          severity: "medium",
          state: "unproven",
          location: `${rel(pkgPath)} · scripts.${hook}`,
          description:
            `scripts.${hook} runs arbitrary code during install. On CI and when a dependency is ` +
            `compromised this is a common execution path.`,
          remediation:
            "Install with --ignore-scripts in CI, and keep this hook minimal and reviewed.",
          proof: { method: "read from package.json", replay: `jq .scripts.${hook} "${rel(pkgPath)}"`, evidence: scripts[hook] },
          regressionHint: "CI: run `pnpm install --ignore-scripts --frozen-lockfile`.",
        });
      }
    }

    const deps: Record<string, string> = {
      ...((pkg.dependencies ?? {}) as Record<string, string>),
      ...((pkg.devDependencies ?? {}) as Record<string, string>),
    };
    for (const [name, spec] of Object.entries(deps)) {
      if (/^(git\+|git:|https?:|file:|github:|[\w.-]+\/[\w.-]+$)/.test(spec)) {
        findings.push({
          id: `dependency-risk:non-registry:${name}`,
          check: "dependency-risk",
          title: `Dependency "${name}" is pulled from outside the registry`,
          severity: "high",
          state: "unproven",
          location: `${rel(pkgPath)} · ${name}`,
          description:
            `"${name}" resolves to "${spec}", which bypasses the registry's integrity checks and ` +
            `publish protections. A moved git ref or a hijacked repo changes your build silently.`,
          remediation: "Prefer a registry version with a pinned integrity hash, or vendor the code.",
          proof: { method: "read from package.json", replay: `jq '.dependencies["${name}"] // .devDependencies["${name}"]' "${rel(pkgPath)}"`, evidence: spec },
        });
      }
    }

    // --- lockfile: denylist match + presence ---
    const lockPath = LOCKFILES.map((f) => join(root, f)).find((p) => existsSync(p));
    if (!lockPath) {
      findings.push({
        id: "dependency-risk:no-lockfile",
        check: "dependency-risk",
        title: "No lockfile: installs are not reproducible",
        severity: "medium",
        state: "unproven",
        location: rel(root),
        description:
          "Without a committed lockfile, two installs can resolve different versions, so a review " +
          "of the code does not pin what actually ships.",
        remediation: "Commit a lockfile and install with --frozen-lockfile in CI.",
      });
      ctx.log("dependency-risk: no lockfile found");
      return findings;
    }

    const locked = parseLockedVersions(readFileSync(lockPath, "utf8"));
    const deny = loadDenylist();
    for (const bad of deny) {
      if (locked.has(`${bad.name}@${bad.version}`)) {
        findings.push({
          id: `dependency-risk:known-bad:${bad.name}@${bad.version}`,
          check: "dependency-risk",
          title: `Known-malicious package locked: ${bad.name}@${bad.version}`,
          severity: "critical",
          state: "proven",
          location: `${rel(lockPath)}`,
          description:
            `${bad.name}@${bad.version} is on the denylist (${bad.advisory}): ${bad.note}. ` +
            `Your lockfile pins exactly this version.`,
          remediation:
            `Upgrade past the affected version now, delete node_modules and the store cache, and ` +
            `rotate any secret that build machines could have exposed.`,
          proof: {
            method: "exact name@version match against the bundled denylist",
            replay: `grep -n "${bad.name}@${bad.version}" "${rel(lockPath)}"`,
            evidence: `${bad.name}@${bad.version} (${bad.advisory})`,
          },
          regressionHint: `CI: fail if the lockfile contains ${bad.name}@${bad.version}.`,
        });
      }
    }

    // --- optional registry signals (opt-in, network) ---
    const opts = (ctx.options["dependency-risk"] ?? {}) as { registry?: boolean | string; osv?: boolean };
    if (opts.osv) {
      if (!ctx.scope.isHostAllowed("https://api.osv.dev/")) ctx.log("dependency-risk: OSV advisories skipped, add api.osv.dev to scope.allowedHosts to enable them");
      else findings.push(...await osvAdvisories(locked, ctx, rel(lockPath)));
    }
    if (opts.registry) {
      const registry = (typeof opts.registry === "string" ? opts.registry : "https://registry.npmjs.org").replace(/\/+$/, "");
      if (!ctx.scope.isHostAllowed(registry)) {
        ctx.log(`dependency-risk: registry signals skipped, add ${new URL(registry).hostname} to scope.allowedHosts to enable them`);
      } else {
        const direct = Object.keys({ ...(pkg.dependencies as object ?? {}), ...(pkg.devDependencies as object ?? {}) });
        findings.push(...await registrySignals(direct, locked, registry, ctx, rel(lockPath)));
      }
    }

    ctx.log(`dependency-risk: root ${rel(root)}, ${locked.size} locked package(s), ${findings.length} finding(s)`);
    return findings;
  },
};

const DAY = 86_400_000;
const NEW_PACKAGE_DAYS = 30;
const FRESH_VERSION_DAYS = 7;
const MAX_PACKAGES = 150;

/**
 * Age signals from the registry for the direct dependencies (opt-in, network).
 * A package first published days ago is the shape of slopsquatting (a name an
 * AI assistant invented, registered by an attacker) and typosquatting; a locked
 * version published in the last days is the window of a maintainer takeover,
 * before the community notices. Leads, never proof: new is not malicious.
 */
export async function registrySignals(direct: string[], locked: Set<string>, registry: string, ctx: CheckContext, lockRel: string, now = Date.now()): Promise<Finding[]> {
  const out: Finding[] = [];
  const names = direct.slice(0, MAX_PACKAGES);
  if (direct.length > MAX_PACKAGES) ctx.log(`dependency-risk: registry signals limited to the first ${MAX_PACKAGES} direct dependencies`);
  for (const name of names) {
    const url = `${registry}/${name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name)}`;
    let doc: { time?: Record<string, string> };
    try {
      const res = await safeFetch(url, ctx.scope, { headers: { accept: "application/json" }, maxBytes: 12 * 1024 * 1024 });
      if (res.status === 404) {
        out.push({
          id: `dependency-risk:not-on-registry:${name}`, check: "dependency-risk",
          title: `Dependency not found on the registry: ${name}`, severity: "medium", state: "unproven", location: lockRel,
          description: `${name} is a direct dependency but ${new URL(registry).host} does not know it. Either it comes from a private registry, or the name was invented (an AI assistant's suggestion) and could be registered by anyone later.`,
          remediation: "Check where it comes from; if it is not yours, remove it before someone publishes a package under that name.",
          proof: { method: "registry lookup", replay: `curl -s -o /dev/null -w '%{http_code}' '${url}'`, evidence: "HTTP 404" },
        });
        continue;
      }
      if (res.status !== 200 || res.truncated) continue;
      doc = JSON.parse(res.body);
    } catch (err) {
      ctx.log(`dependency-risk: ${name}: ${(err as Error).message}`);
      continue;
    }
    const time = doc.time ?? {};
    const created = Date.parse(time.created ?? "");
    if (Number.isFinite(created) && now - created < NEW_PACKAGE_DAYS * DAY) {
      const days = Math.floor((now - created) / DAY);
      out.push({
        id: `dependency-risk:new-package:${name}`, check: "dependency-risk",
        title: `Very new package: ${name} (first published ${days} day(s) ago)`, severity: "medium", state: "unproven", location: lockRel,
        description: `${name} appeared on the registry ${days} day(s) ago. Fresh packages with plausible names are how slopsquatting and typosquatting land in projects.`,
        remediation: "Check that this is the package you meant (author, repository, downloads). Prefer an established one.",
        proof: { method: "registry metadata: time.created", replay: `npm view ${name} time.created`, evidence: time.created! },
      });
    }
    for (const v of [...locked].filter((x) => x.startsWith(`${name}@`)).map((x) => x.slice(name.length + 1))) {
      const at = Date.parse(time[v] ?? "");
      if (Number.isFinite(at) && now - at < FRESH_VERSION_DAYS * DAY) {
        const days = Math.floor((now - at) / DAY);
        out.push({
          id: `dependency-risk:fresh-version:${name}@${v}`, check: "dependency-risk",
          title: `Locked version published ${days} day(s) ago: ${name}@${v}`, severity: "low", state: "unproven", location: lockRel,
          description: `${name}@${v} is days old. Hijacked versions are usually caught within days; locking one this early skips that window.`,
          remediation: "Wait a few days before adopting new versions (a minimum release age in your package manager), or review this release.",
          proof: { method: "registry metadata: time[version]", replay: `npm view ${name}@${v} time`, evidence: time[v]! },
        });
      }
    }
  }
  return out;
}

const OSV = "https://api.osv.dev/v1";
const OSV_SEVERITY: Record<string, Finding["severity"]> = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

/**
 * Known advisories for every locked npm package, from OSV (the database behind
 * osv-scanner and GitHub's advisories). Opt-in, network: the package names and
 * versions go to api.osv.dev, nothing else. A locked version inside an
 * advisory's range is reported as a lead: affected, exploitability not proven.
 */
export async function osvAdvisories(locked: Set<string>, ctx: CheckContext, lockRel: string): Promise<Finding[]> {
  // Entries are name@version (npm) or Ecosystem::name@version (PyPI::langflow@1.8.0), as OSV names ecosystems.
  const pkgs = [...locked].map((x) => {
    const sep = x.indexOf("::");
    const ecosystem = sep > 0 ? x.slice(0, sep) : "npm";
    const rest = sep > 0 ? x.slice(sep + 2) : x;
    const i = rest.lastIndexOf("@");
    return { ecosystem, name: rest.slice(0, i), version: rest.slice(i + 1) };
  }).filter((p) => p.name && p.version);
  const hits: { ecosystem: string; name: string; version: string; id: string }[] = [];
  for (let i = 0; i < pkgs.length; i += 1000) {
    const batch = pkgs.slice(i, i + 1000);
    try {
      const res = await safeFetch(`${OSV}/querybatch`, ctx.scope, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ queries: batch.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }), maxBytes: 8 * 1024 * 1024 });
      const results = (JSON.parse(res.body) as { results?: { vulns?: { id: string }[] }[] }).results ?? [];
      results.forEach((r, k) => (r.vulns ?? []).forEach((v) => hits.push({ ...batch[k]!, id: v.id })));
    } catch (err) { ctx.log(`dependency-risk: OSV query failed: ${(err as Error).message}`); return []; }
  }
  const out: Finding[] = [];
  const details = new Map<string, { summary?: string; aliases?: string[]; database_specific?: { severity?: string } }>();
  for (const id of [...new Set(hits.map((h) => h.id))].slice(0, 80)) {
    try { details.set(id, JSON.parse((await safeFetch(`${OSV}/vulns/${encodeURIComponent(id)}`, ctx.scope)).body)); } catch { /* summary stays empty */ }
  }
  for (const h of hits) {
    const d = details.get(h.id);
    const sev = OSV_SEVERITY[(d?.database_specific?.severity ?? "").toUpperCase()] ?? "medium";
    const cve = d?.aliases?.find((a) => a.startsWith("CVE-"));
    out.push({
      id: `dependency-risk:advisory:${h.name}@${h.version}:${h.id}`, check: "dependency-risk",
      title: `${h.name}@${h.version} is affected by ${h.id}${cve ? ` (${cve})` : ""}${d?.summary ? `: ${d.summary.slice(0, 120)}` : ""}`,
      severity: sev, state: "unproven", location: lockRel,
      description: `The locked version ${h.name}@${h.version} falls in the affected range of ${h.id}. Whether your app reaches the vulnerable code is not proven.`,
      remediation: `Upgrade ${h.name} past the fixed version listed in the advisory (https://osv.dev/vulnerability/${h.id}).`,
      proof: { method: "OSV query for the exact locked version", replay: `curl -s https://api.osv.dev/v1/query -d '{"package":{"name":"${h.name}","ecosystem":"${h.ecosystem}"},"version":"${h.version}"}'`, evidence: h.id },
    });
  }
  ctx.log(`dependency-risk: OSV, ${pkgs.length} package(s) queried, ${out.length} advisory match(es)`);
  return out;
}
