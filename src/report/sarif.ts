// SARIF 2.1.0 export, so findings flow into GitHub code scanning and any SARIF
// viewer. Written against GitHub's "SARIF support for code scanning" page:
// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
//
//   - every rule carries id, shortDescription, fullDescription and help (the
//     page lists them as required), tags, precision and, for proven results, a
//     security-severity GitHub reads to rank the alert;
//   - a lead is a "note" under its own rule (`<check>/lead`) with no security
//     severity, so it never shows as a critical alert next to a proven one;
//   - every result has exactly one location with a uri relative to the
//     repository root and a region. GitHub rejects a file that mixes uri
//     schemes and only shows results located in the repository, so a finding
//     about a URL, a host or a config option is anchored to the config file
//     (line 1) and the original location stays in the message and properties;
//   - partialFingerprints.primaryLocationLineHash is derived from the finding's
//     stable id (GitHub only reads that key), so an alert keeps its identity
//     between runs even when many findings share the config-file anchor;
//   - the documented limits are enforced: 25,000 results and rules per run,
//     20 tags per rule, 10 MB gzipped (leads are dropped first, then the
//     lowest severities), and messages are bounded.
// Fixed findings are not emitted: their absence is what closes the alert.

import { createHash } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { dirname, isAbsolute, resolve } from "node:path";
import type { RunResult } from "../core/runner.js";
import type { Finding, Severity } from "../core/types.js";
import { relative } from "../core/walk.js";

export interface SarifOptions {
  /** Repository root that uris are made relative to (GitHub: the checkout). Default: cwd. */
  repoRoot?: string;
  /** Absolute project directory the checks scanned; relative locations resolve against it. */
  projectDir?: string;
  /** Config file, the anchor for findings that are not about a file in the repository. */
  configPath?: string;
  /** Check name -> one-line title (from the registry). */
  titles?: Record<string, string>;
  /** Tool version written to the driver. */
  version?: string;
}

/** Limits from GitHub's SARIF page ("Validating your SARIF file"). */
export const SARIF_LIMITS = { gzipBytes: 10 * 1024 * 1024, results: 25_000, rules: 25_000, tags: 20, descriptionChars: 1024 } as const;

const SECURITY_SEVERITY: Record<Severity, string | undefined> = { critical: "9.5", high: "8.0", medium: "5.5", low: "2.0", info: undefined };
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const MAX_MESSAGE = 4000;

function level(sev: Severity, state: Finding["state"]): "error" | "warning" | "note" {
  if (state !== "proven") return "note";
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

const clip = (s: string, n: number) => (s.length <= n ? s : s.slice(0, n - 1) + "…");
const ruleIdOf = (f: Finding) => (f.state === "proven" ? f.check : `${f.check}/lead`);

interface Located { uri: string; startLine: number; anchored: boolean }

/** Map a finding location to a repository-relative uri and a line. */
export function locate(location: string, opts: SarifOptions = {}): Located {
  const root = resolve(opts.repoRoot ?? process.cwd());
  const anchor = (): Located => ({ uri: opts.configPath ? relative(root, resolve(opts.configPath)) || "crenel.config.yaml" : "crenel.config.yaml", startLine: 1, anchored: true });
  // Inside the repository and not a directory (code scanning shows files only).
  const inside = (abs: string) => {
    const r = relative(root, abs);
    if (!r || r.startsWith("..") || isAbsolute(r)) return null;
    try { if (statSync(resolve(abs)).isDirectory()) return null; } catch { /* a file not on disk: keep the path */ }
    return r;
  };
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(location) || /\s/.test(location.trim())) return anchor();
  const m = location.match(/^(.*?):(\d+)$/);
  const path = m ? m[1]! : location;
  const line = m ? Math.max(1, Number(m[2])) : 1;
  if (!path) return anchor();
  if (isAbsolute(path)) {
    const r = inside(path);
    return r ? { uri: r, startLine: line, anchored: false } : anchor();
  }
  if (opts.projectDir) {
    const full = resolve(opts.projectDir, path);
    const r = existsSync(full) ? inside(full) : null;
    return r ? { uri: r, startLine: line, anchored: false } : anchor();
  }
  // No project directory known (library use): keep a plain relative path.
  return path.startsWith("..") ? anchor() : { uri: path.replace(/\\/g, "/"), startLine: line, anchored: false };
}

/**
 * The options `crenel scan --sarif` uses, shared with the console's export:
 * locations repository-relative to the cwd (as in a GitHub checkout), the
 * project dir resolved against the config file, rule titles from the registry.
 */
export function sarifOptionsFor(projectDir: string, configPath: string, titles: Record<string, string>): SarifOptions {
  const configDir = dirname(resolve(configPath));
  return {
    repoRoot: process.cwd(),
    projectDir: isAbsolute(projectDir) ? projectDir : resolve(configDir, projectDir),
    configPath: resolve(configPath),
    titles,
  };
}

export function toSarif(result: RunResult, opts: SarifOptions = {}): string {
  // Proven first, highest severity first: what survives the limits.
  let findings = result.findings
    .filter((f) => f.state !== "fixed")
    .sort((a, b) => Number(b.state === "proven") - Number(a.state === "proven") || RANK[b.severity] - RANK[a.severity])
    .slice(0, SARIF_LIMITS.results);
  let text = build(result, findings, opts);
  // 10 MB gzipped is a hard limit: the whole file would be rejected.
  while (gzipSync(text).length > SARIF_LIMITS.gzipBytes && findings.length) {
    const leads = findings.filter((f) => f.state !== "proven");
    findings = leads.length ? findings.filter((f) => f.state === "proven") : findings.slice(0, Math.floor(findings.length / 2));
    text = build(result, findings, opts, true);
  }
  return text;
}

function build(result: RunResult, findings: Finding[], opts: SarifOptions, truncated = false): string {
  const titles = opts.titles ?? {};
  const rules = new Map<string, { id: string; check: string; lead: boolean; worst: Severity }>();
  for (const f of findings) {
    const id = ruleIdOf(f);
    const cur = rules.get(id);
    if (!cur) rules.set(id, { id, check: f.check, lead: f.state !== "proven", worst: f.severity });
    else if (RANK[f.severity] > RANK[cur.worst]) cur.worst = f.severity;
  }
  const ruleList = [...rules.values()].slice(0, SARIF_LIMITS.rules);
  const index = new Map(ruleList.map((r, i) => [r.id, i]));
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Crenel",
            ...(opts.version ? { version: opts.version } : {}),
            informationUri: "https://github.com/GlamgarOnDiscord/crenel",
            rules: ruleList.map((r) => {
              const title = titles[r.check] ?? r.check;
              const short = clip(r.lead ? `${title} (lead, not proven)` : title, SARIF_LIMITS.descriptionChars);
              const full = clip(r.lead
                ? `Crenel check ${r.check}: ${title}. A lead is surfaced without a replayable proof; it never fails a build.`
                : `Crenel check ${r.check}: ${title}. Reported only with a replayable proof.`, SARIF_LIMITS.descriptionChars);
              const sev = r.lead ? undefined : SECURITY_SEVERITY[r.worst];
              return {
                id: r.id,
                name: r.check,
                shortDescription: { text: short },
                fullDescription: { text: full },
                help: {
                  text: `${full} The result message carries the fix. Check reference: docs/CHECKS.md (${r.check}).`,
                  markdown: `${full}\n\nThe result message carries the fix. Check reference: \`docs/CHECKS.md\`, section \`${r.check}\`.`,
                },
                defaultConfiguration: { level: r.lead ? "note" : level(r.worst, "proven") },
                properties: {
                  tags: ["security", "crenel", r.lead ? "lead" : "proven"].slice(0, SARIF_LIMITS.tags),
                  precision: r.lead ? "low" : "very-high",
                  ...(sev ? { "security-severity": sev } : { "problem.severity": "recommendation" }),
                },
              };
            }),
          },
        },
        // executionSuccessful=false when any check threw, so a partial run is
        // not consumed as a clean one by GitHub code scanning.
        invocations: [
          {
            executionSuccessful: result.errors.length === 0,
            toolExecutionNotifications: [
              ...result.errors.map((e) => ({ level: "error", message: { text: `${e.check}: ${e.message}` } })),
              ...(truncated ? [{ level: "warning", message: { text: "Results were cut to stay under GitHub's 10 MB gzipped SARIF limit." } }] : []),
            ],
          },
        ],
        results: findings.filter((f) => index.has(ruleIdOf(f))).map((f) => {
          const at = locate(f.location, opts);
          const where = at.anchored ? ` Location: ${f.location}.` : "";
          return {
            ruleId: ruleIdOf(f),
            ruleIndex: index.get(ruleIdOf(f)),
            level: level(f.severity, f.state),
            message: { text: clip(`${f.title}.${where} ${f.remediation}`, MAX_MESSAGE) },
            locations: [{ physicalLocation: { artifactLocation: { uri: at.uri }, region: { startLine: at.startLine } } }],
            // GitHub reads only primaryLocationLineHash; ours comes from the
            // finding's stable id, so the alert survives between runs.
            partialFingerprints: {
              primaryLocationLineHash: `${createHash("sha256").update(f.id).digest("hex").slice(0, 16)}:1`,
              crenelFindingId: f.id,
            },
            properties: { severity: f.severity, state: f.state, id: f.id, location: f.location },
          };
        }),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
