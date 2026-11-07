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
import { webhookSignature } from "../checks/webhook-signature.js";
import { ssrf } from "../checks/ssrf.js";
import { liveBundle } from "../checks/live-bundle.js";
import { exposedFiles } from "../checks/exposed-files.js";
import { graphql } from "../checks/graphql.js";
import { openRedirect } from "../checks/open-redirect.js";
import { nextMiddleware } from "../checks/next-middleware.js";
import { subdomainTakeover } from "../checks/subdomain-takeover.js";
import { emailDns } from "../checks/email-dns.js";
import { transport } from "../checks/transport.js";
import { gitHistory } from "../checks/git-history.js";
import { storageBuckets } from "../checks/storage-buckets.js";
import { devServer } from "../checks/dev-server.js";
import { aiInfra } from "../checks/ai-infra.js";
import { vercelPreview } from "../checks/vercel-preview.js";
import { cacheDeception } from "../checks/cache-deception.js";
import { authConfig } from "../checks/auth-config.js";
import { authVariants } from "../checks/auth-variants.js";
import { nextImage } from "../checks/next-image.js";
import { apiDocs } from "../checks/api-docs.js";
import { supabaseRpc } from "../checks/supabase-rpc.js";

export const REGISTRY: Check[] = [exposedSecrets, dependencyRisk, ciHardening, headers, cloudflareAudit, mcpSurface, dockerfile, committedEnv, sourcemaps, publicEnv, tlsVerification, jwtConfig, committedCredentials, baasExposure, webhookSignature, ssrf, liveBundle, exposedFiles, graphql, openRedirect, nextMiddleware, subdomainTakeover, emailDns, transport, gitHistory, storageBuckets, devServer, aiInfra, vercelPreview, cacheDeception, authConfig, authVariants, nextImage, apiDocs, supabaseRpc, authzMatrix];

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
