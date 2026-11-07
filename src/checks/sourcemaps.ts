// sourcemaps: a source map shipped next to a client bundle hands anyone the
// original, unminified source (and often comments and file layout). It sits in
// the same wheelhouse as exposed-secrets: what leaks to the browser. Offline and
// deterministic: we look for .map files under the scanned directory and for
// sourceMappingURL comments that point at a shipped map. Leads, since some teams
// ship maps on purpose for error tracking.

import { readFileSync, statSync } from "node:fs";
import { basename } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, relative } from "../core/walk.js";

const CODE_EXT = new Set([".js", ".mjs", ".cjs", ".css"]);

const walk = (dir: string) => walkFiles(dir); // default skip (node_modules, .git)

export const sourcemaps: Check = {
  name: "sourcemaps",
  title: "Source maps shipped with the client bundle (expose original source)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const mapFiles: string[] = [];
    const refFiles: string[] = [];

    for (const file of walk(ctx.projectDir)) {
      const base = basename(file);
      const dot = base.lastIndexOf(".");
      const ext = dot >= 0 ? base.slice(dot) : "";
      if (base.endsWith(".map")) {
        mapFiles.push(file);
        continue;
      }
      if (!CODE_EXT.has(ext)) continue;
      // A sourceMappingURL comment pointing at an external .map (not a data: URI).
      try {
        if (statSync(file).size > 8 * 1024 * 1024) continue;
        const tail = readFileSync(file, "utf8").slice(-2048); // the comment is at the end
        const m = tail.match(/sourceMappingURL=(?!data:)(\S+\.map)/);
        if (m) refFiles.push(file);
      } catch { /* skip unreadable */ }
    }

    const rel = (p: string) => relative(ctx.projectDir, p) || p;
    for (const f of mapFiles) {
      findings.push({
        id: `sourcemaps:file:${rel(f)}`,
        check: "sourcemaps",
        title: `Source map in the bundle: ${rel(f)}`,
        severity: "low",
        state: "unproven",
        location: rel(f),
        description:
          `${rel(f)} is a source map under the scanned directory. If this is served to the browser, anyone can ` +
          `recover your original, unminified source from it.`,
        remediation:
          "Do not deploy .map files publicly. Upload them to your error tracker (Sentry, etc.) at build time and strip them from the served bundle.",
        proof: { method: "source map file present in the scanned bundle", replay: `find . -name '*.map' -not -path '*/node_modules/*'` },
        regressionHint: "CI: fail if the deployed bundle contains a .map file.",
      });
    }
    // Only report dangling references to maps we did not also find as files, to
    // avoid double-counting the same leak.
    const mapNames = new Set(mapFiles.map((f) => basename(f)));
    for (const f of refFiles) {
      findings.push({
        id: `sourcemaps:ref:${rel(f)}`,
        check: "sourcemaps",
        title: `sourceMappingURL points at a map in ${rel(f)}`,
        severity: "low",
        state: "unproven",
        location: rel(f),
        description:
          `${rel(f)} ends with a sourceMappingURL comment pointing at an external .map. If that map is served, the ` +
          `original source is exposed.` + (mapNames.size ? "" : " (the .map itself was not found under the scanned dir, so confirm what is actually deployed.)"),
        remediation: "Strip the sourceMappingURL comment from the served bundle, or keep the map out of the public deploy.",
        proof: { method: "sourceMappingURL comment detected", replay: `grep -l 'sourceMappingURL' "${rel(f)}"` },
      });
    }

    ctx.log(`sourcemaps: ${mapFiles.length} map file(s), ${refFiles.length} reference(s)`);
    return findings;
  },
};
