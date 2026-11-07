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

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";
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

    ctx.log(`dependency-risk: root ${rel(root)}, ${locked.size} locked package(s), ${findings.length} finding(s)`);
    return findings;
  },
};
