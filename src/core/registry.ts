// The check registry. Adding a check means importing it here. Keeping this list
// explicit (rather than auto-discovering files) means a published build never
// runs a check the maintainers did not review.

import type { Check } from "./types.js";
import { exposedSecrets } from "../checks/exposed-secrets.js";
import { authzMatrix } from "../checks/authz-matrix.js";
import { dependencyRisk } from "../checks/dependency-risk.js";
import { ciHardening } from "../checks/ci-hardening.js";
import { headers } from "../checks/headers.js";
import { cloudflareAudit } from "../checks/cloudflare-audit.js";
import { mcpSurface } from "../checks/mcp-surface.js";
import { dockerfile } from "../checks/dockerfile.js";
import { committedEnv } from "../checks/committed-env.js";
import { sourcemaps } from "../checks/sourcemaps.js";
import { publicEnv } from "../checks/public-env.js";
import { tlsVerification } from "../checks/tls-verification.js";
import { jwtConfig } from "../checks/jwt-config.js";
import { committedCredentials } from "../checks/committed-credentials.js";
import { baasExposure } from "../checks/baas-exposure.js";

export const REGISTRY: Check[] = [exposedSecrets, dependencyRisk, ciHardening, headers, cloudflareAudit, mcpSurface, dockerfile, committedEnv, sourcemaps, publicEnv, tlsVerification, jwtConfig, committedCredentials, baasExposure, authzMatrix];

export function resolveChecks(names: string[]): Check[] {
  if (names.length === 0) {
    // Default: every read-only check. Active checks must be named explicitly.
    return REGISTRY.filter((c) => c.readOnly);
  }
  const byName = new Map(REGISTRY.map((c) => [c.name, c]));
  const out: Check[] = [];
  for (const n of names) {
    const c = byName.get(n);
    if (!c) throw new Error(`Unknown check: "${n}". Run "crenel list" to see available checks.`);
    out.push(c);
  }
  return out;
}
