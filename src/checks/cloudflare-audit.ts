// cloudflare-audit: ingest the findings.json produced by Cloudflare's
// security-audit-skill (github.com/cloudflare/security-audit-skill) and
// normalise it into Crenel findings. We do not run the skill here (it runs in a
// Claude Code agent against a codebase you own); we consume its report so its
// results live alongside Crenel's own checks, with the same proof discipline:
//
//   - verdict "confirmed"      -> proven (it has a source trace and a result)
//   - verdict "needs_validation" -> lead (an unresolved fact, no severity)
//   - verdict "rejected"       -> dropped
//
// Point it at the report in config: options.cloudflare-audit.report = "path".

import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { Check, CheckContext, Finding, Severity } from "../core/types.js";

interface Trace { kind: string; file: string; line: number; scope?: string; description?: string }
// Matches skills/security-audit/report-schema.json: an array of per-verdict
// objects. remediation is an OBJECT ({ strategy, code_changes }), not a string.
interface CfFinding {
  verdict: "confirmed" | "needs_validation" | "rejected";
  fingerprint: string;
  title: string;
  description?: string;
  root_cause?: string;
  remediation?: { strategy?: string; code_changes?: { file_name: string; fixed_code: string }[] };
  trace?: Trace[];
  severity?: { overall_severity?: "informational" | "low" | "medium" | "high" | "critical" };
}

function remediationText(r: CfFinding): string {
  const strat = r.remediation?.strategy;
  const files = r.remediation?.code_changes?.map((c) => c.file_name).filter(Boolean) ?? [];
  if (strat) return files.length ? `${strat} (fichiers: ${files.join(", ")})` : strat;
  return "Voir le rapport détaillé du skill (FINDINGS-DETAIL.md).";
}

function mapSeverity(s?: string): Severity {
  if (s === "informational") return "info";
  if (s === "low" || s === "medium" || s === "high" || s === "critical") return s;
  return "medium";
}

function locationOf(trace?: Trace[]): string {
  if (!trace || trace.length === 0) return "(no trace)";
  const sink = trace.find((t) => t.kind === "sink") ?? trace[trace.length - 1]!;
  return `${sink.file}:${sink.line}`;
}

export const cloudflareAudit: Check = {
  name: "cloudflare-audit",
  title: "Findings from Cloudflare's security-audit-skill (normalised)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const opts = (ctx.options["cloudflare-audit"] ?? {}) as { report?: string };
    if (!opts.report) {
      return [{
        id: "cloudflare-audit:not-configured",
        check: "cloudflare-audit",
        title: "Audit Cloudflare non branché",
        severity: "info",
        state: "unproven",
        location: ctx.projectDir,
        description: "Lancez le skill cloudflare/security-audit-skill sur ce dépôt, puis pointez options.cloudflare-audit.report vers son findings.json pour l'ingérer ici.",
        remediation: "npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit, puis 'security audit this codebase'.",
      }];
    }
    const path = isAbsolute(opts.report) ? opts.report : join(ctx.projectDir, opts.report);
    if (!existsSync(path)) {
      ctx.log(`cloudflare-audit: report not found at ${path}`);
      return [];
    }
    let records: CfFinding[];
    try {
      records = JSON.parse(readFileSync(path, "utf8"));
      if (!Array.isArray(records)) throw new Error("findings.json is not an array");
    } catch (err) {
      ctx.log(`cloudflare-audit: ${(err as Error).message}`);
      return [];
    }

    const out: Finding[] = [];
    for (const r of records) {
      if (r.verdict === "rejected") continue;
      const proven = r.verdict === "confirmed";
      out.push({
        id: `cloudflare-audit:${r.fingerprint}`,
        check: "cloudflare-audit",
        title: r.title,
        severity: proven ? mapSeverity(r.severity?.overall_severity) : "medium",
        state: proven ? "proven" : "unproven",
        location: locationOf(r.trace),
        description: r.description ?? r.root_cause ?? r.title,
        remediation: remediationText(r),
        proof: proven && r.trace?.length
          ? { method: "trace source du skill security-audit", replay: r.trace.map((t) => `${t.kind} ${t.file}:${t.line}`).join(" -> ") }
          : undefined,
      });
    }
    ctx.log(`cloudflare-audit: ${records.length} record(s), ${out.length} imported`);
    return out;
  },
};
