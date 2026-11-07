// mcp-surface: find committed agent / MCP configuration, a real 2026 attack
// surface. These files routinely hold provider tokens and declare servers that
// run local binaries or reach URLs; a poisoned or leaked one turns an agent into
// an execution and exfiltration path (SANDWORM_MODE poisoned agent configs;
// GitGuardian counted tens of thousands of secrets in MCP config files).
//
// Deterministic and offline: we look at a fixed set of known config locations
// under the repo root, parse them, and report what is exposed. Everything is a
// lead (a surface to review), never a proven vuln. Secret *values* are the job of
// the exposed-secrets check; here we flag the surface and its shape.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";

// Walk up to the nearest repo-ish root so pointing at a built bundle still finds
// configs that live above it.
function findRoot(start: string): string {
  let dir = start;
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, "package.json")) || existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return start;
}

// Known agent / MCP config locations, relative to the root.
const KNOWN_CONFIGS = [
  ".mcp.json",
  "mcp.json",
  "claude_desktop_config.json",
  ".claude/settings.json",
  ".claude/settings.local.json",
  ".cursor/mcp.json",
  ".vscode/mcp.json",
  ".continue/config.json",
  ".windsurf/mcp_config.json",
];

// Pull the server map out of the various shapes these files use.
function serversOf(data: unknown): Record<string, unknown> {
  if (!data || typeof data !== "object") return {};
  const d = data as Record<string, unknown>;
  const map = d.mcpServers ?? d.servers ?? d.mcp;
  return map && typeof map === "object" ? (map as Record<string, unknown>) : {};
}

export const mcpSurface: Check = {
  name: "mcp-surface",
  title: "Committed agent/MCP configuration exposed to the repo",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const root = findRoot(ctx.projectDir);
    const rel = (p: string) => relative(ctx.projectDir, p) || relative(root, p) || p;

    for (const name of KNOWN_CONFIGS) {
      const full = join(root, name);
      if (!existsSync(full)) continue;
      let data: unknown;
      let raw: string;
      try {
        raw = readFileSync(full, "utf8");
        data = JSON.parse(raw);
      } catch {
        // present but unparseable: still worth noting it exists
        findings.push({
          id: `mcp-surface:present:${name}`,
          check: "mcp-surface",
          title: `Agent/MCP config committed: ${name}`,
          severity: "low",
          state: "unproven",
          location: rel(full),
          description: `${name} is committed. Agent configs often hold tokens and define servers; review that this one is meant to ship.`,
          remediation: "Keep agent/MCP config out of version control if it holds secrets; use env or a secret store.",
          proof: { method: "known agent/MCP config path present", replay: `test -f "${name}"` },
        });
        continue;
      }

      const servers = serversOf(data);
      const serverNames = Object.keys(servers);
      const runsBinary: string[] = [];
      const hasEnv: string[] = [];
      for (const [sname, sval] of Object.entries(servers)) {
        if (sval && typeof sval === "object") {
          const s = sval as Record<string, unknown>;
          if (typeof s.command === "string") runsBinary.push(sname);
          if (s.env && typeof s.env === "object") hasEnv.push(sname);
        }
      }

      findings.push({
        id: `mcp-surface:config:${name}`,
        check: "mcp-surface",
        title: `Agent/MCP config committed: ${name} (${serverNames.length} server${serverNames.length === 1 ? "" : "s"})`,
        severity: runsBinary.length > 0 ? "medium" : "low",
        state: "unproven",
        location: rel(full),
        description:
          `${name} declares ${serverNames.length} MCP server(s)${serverNames.length ? `: ${serverNames.join(", ")}` : ""}. ` +
          (runsBinary.length ? `${runsBinary.join(", ")} run a local command (arbitrary execution if the config is tampered with). ` : "") +
          (hasEnv.length ? `${hasEnv.join(", ")} carry an env block that may hold secrets. ` : "") +
          `Review that every server is trusted and that no secret is committed here.`,
        remediation:
          "Pin and review each MCP server, keep secrets out of the committed file (use env/secret store), and treat any untrusted server as code execution.",
        proof: { method: "parsed known agent/MCP config", replay: `jq '.mcpServers // .servers' "${name}"` },
        regressionHint: "CI: fail if a committed agent/MCP config gains an unreviewed server or an inline secret.",
      });
    }

    ctx.log(`mcp-surface: root ${relative(ctx.projectDir, root) || "."}, ${findings.length} config(s)`);
    return findings;
  },
};
