// SARIF 2.1.0 export, so findings flow into GitHub code scanning and any SARIF
// viewer. Only proven findings and leads are emitted; a lead is a "note" so it
// never shows as a blocking alert. Severity maps to SARIF level.

import type { RunResult } from "../core/runner.js";
import type { Finding, Severity } from "../core/types.js";

function level(sev: Severity, state: Finding["state"]): "error" | "warning" | "note" {
  if (state !== "proven") return "note";
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

// "path:line" -> { uri, startLine } ; a bare path or URL keeps uri only.
function physicalLocation(location: string): Record<string, unknown> {
  const m = location.match(/^(.*):(\d+)$/);
  const uri = m ? m[1]! : location;
  const artifactLocation = { uri };
  return m
    ? { artifactLocation, region: { startLine: Number(m[2]) } }
    : { artifactLocation };
}

export function toSarif(result: RunResult): string {
  const rulesSeen = new Map<string, { id: string; name: string }>();
  for (const f of result.findings) {
    if (!rulesSeen.has(f.check)) rulesSeen.set(f.check, { id: f.check, name: f.check });
  }
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Crenel",
            informationUri: "https://github.com/crenel/crenel",
            rules: [...rulesSeen.values()].map((r) => ({ id: r.id, name: r.name })),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.check,
          level: level(f.severity, f.state),
          message: { text: `${f.title}. ${f.remediation}` },
          locations: [{ physicalLocation: physicalLocation(f.location) }],
          properties: { severity: f.severity, state: f.state, id: f.id },
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
