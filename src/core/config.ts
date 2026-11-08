// Config loading and validation. The config file is the single place where a
// user declares what they own and what they allow. We validate it with zod so a
// typo fails loudly instead of silently widening scope.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { loadOpenApi } from "./openapi.js";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

// An environment variable name, upper case. A Client ID (32 hex + ".access") or
// a 64-hex secret never matches, so a value pasted by mistake is refused.
const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/;

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
    // Cloudflare Access service tokens, per exact declared host. Only the NAMES
    // of the environment variables: the schema has no field for a value, so a
    // secret pasted in the config fails validation instead of being used.
    access: z.record(
      z.string().trim().min(1),
      z.object({
        clientIdEnv: z.string().regex(ENV_NAME, "nom de variable d'environnement attendu (ex. CRENEL_CF_ACCESS_ID), jamais la valeur"),
        clientSecretEnv: z.string().regex(ENV_NAME, "nom de variable d'environnement attendu (ex. CRENEL_CF_ACCESS_SECRET), jamais la valeur"),
      }).strict(),
    ).optional(),
    /** Pace every live request of a run (requests per second). */
    ratePerSec: z.number().positive().max(1000).optional(),
    /** Hard cap on live requests in one run. */
    maxRequests: z.number().int().positive().optional(),
  }).strict().superRefine((s, ctx) => {
    const hosts = new Set(s.allowedHosts.map((h) => h.toLowerCase()));
    for (const h of Object.keys(s.access ?? {})) {
      if (!hosts.has(h.toLowerCase().trim())) ctx.addIssue({ code: "custom", path: ["access", h], message: `${h} n'est pas dans allowedHosts` });
    }
  }),
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
  return withOpenApi(result.data, path);
}

// options.authz-matrix.openapi: a spec file (relative to the config) whose GET
// object routes are added to the declared resources. Declared ones win on a
// name clash, so a hand-written entry can always override the import.
function withOpenApi(config: Config, configPath: string): Config {
  const authz = config.options["authz-matrix"] as { openapi?: unknown; resources?: { name: string }[] } | undefined;
  if (!authz || typeof authz.openapi !== "string") return config;
  const file = resolve(dirname(configPath), authz.openapi);
  let imported;
  try {
    imported = loadOpenApi(file);
  } catch (err) {
    throw new Error(`Cannot read options.authz-matrix.openapi (${file}): ${(err as Error).message}`);
  }
  const declared = authz.resources ?? [];
  const taken = new Set(declared.map((r) => r.name));
  const resources = [...declared, ...imported.filter((r) => !taken.has(r.name))];
  return { ...config, options: { ...config.options, "authz-matrix": { ...authz, resources } } };
}

/** The Scope settings a config declares (callers add signal and onRequest). */
export function scopeSettings(s: Config["scope"]) {
  return {
    allowedHosts: s.allowedHosts,
    allowActiveTesting: s.allowActiveTesting,
    allowPrivate: s.allowPrivate,
    stagingUrl: s.stagingUrl,
    access: s.access,
    ratePerSec: s.ratePerSec,
    maxRequests: s.maxRequests,
  };
}
