// Config loading and validation. The config file is the single place where a
// user declares what they own and what they allow. We validate it with zod so a
// typo fails loudly instead of silently widening scope.

import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

export const ConfigSchema = z.object({
  /** Human label for the target, shown in reports. */
  project: z.string().default("unnamed project"),
  /** Path to the code to scan, relative to the config file. */
  projectDir: z.string().default("."),
  scope: z.object({
    // Reject empty host strings: an empty entry would match any URL with an
    // empty hostname (file:, data:), silently widening scope.
    allowedHosts: z.array(z.string().trim().min(1, "un hôte ne peut pas être vide")).default([]),
    allowActiveTesting: z.boolean().default(false),
    allowPrivate: z.boolean().default(false),
    stagingUrl: z.string().url().optional(),
  }).strict(),
  /** Which checks to run. Empty means "all read-only checks". */
  checks: z.array(z.string()).default([]),
  /** Per-check options, keyed by check name. */
  options: z.record(z.string(), z.unknown()).default({}),
}).strict();

export type Config = z.infer<typeof ConfigSchema>;

export function loadConfig(path: string): Config {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new Error(`Cannot read config file: ${path}`);
  }
  const parsed = parseYaml(raw);
  const result = ConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("\n");
    throw new Error(`Invalid config (${path}):\n${issues}`);
  }
  return result.data;
}
