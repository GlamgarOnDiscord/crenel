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
import { errorDisclosure } from "../checks/error-disclosure.js";
import { corsReflection } from "../checks/cors-reflection.js";
import { headerInjection } from "../checks/header-injection.js";
import { dependencyExposure } from "../checks/dependency-exposure.js";
import { graphqlInjection } from "../checks/graphql-injection.js";
import { reflectedXss } from "../checks/reflected-xss.js";
import { defaultCreds } from "../checks/default-creds.js";
import { graphqlSsrf } from "../checks/graphql-ssrf.js";
import { graphql } from "../checks/graphql.js";
import { metricsExposed } from "../checks/metrics-exposed.js";
import { jwtVerification } from "../checks/jwt-verification.js";
import { authInjection } from "../checks/auth-injection.js";
import { directoryListing } from "../checks/directory-listing.js";
import { liveSsrf } from "../checks/live-ssrf.js";
import { commandInjection } from "../checks/command-injection.js";
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
import { cachePoisoning } from "../checks/cache-poisoning.js";
import { businessLogic } from "../checks/business-logic.js";
import { supabaseFunctions } from "../checks/supabase-functions.js";
import { authzWrite } from "../checks/authz-write.js";
import { massAssignment } from "../checks/mass-assignment.js";
import { race } from "../checks/race.js";
import { replay } from "../checks/replay.js";

import { nestedAuthz } from "../checks/nested-authz.js";
import { paramInjection } from "../checks/param-injection.js";
import { functionAuthz } from "../checks/function-authz.js";
import { storedXss } from "../checks/stored-xss.js";
import { signupPrivilege } from "../checks/signup-privilege.js";
import { dataExposure } from "../checks/data-exposure.js";
export const REGISTRY: Check[] = [exposedSecrets, dependencyRisk, ciHardening, headers, cloudflareAudit, mcpSurface, dockerfile, committedEnv, sourcemaps, publicEnv, tlsVerification, jwtConfig, committedCredentials, baasExposure, webhookSignature, ssrf, liveBundle, exposedFiles, graphql, openRedirect, nextMiddleware, subdomainTakeover, emailDns, transport, gitHistory, storageBuckets, devServer, aiInfra, vercelPreview, cacheDeception, authConfig, authVariants, nextImage, apiDocs, supabaseRpc, cachePoisoning, businessLogic, supabaseFunctions, authzMatrix, authzWrite, massAssignment, race, metricsExposed, jwtVerification, authInjection, directoryListing, liveSsrf, commandInjection, errorDisclosure, corsReflection, headerInjection, dependencyExposure, graphqlInjection, reflectedXss, graphqlSsrf, defaultCreds, replay, nestedAuthz, paramInjection, functionAuthz, storedXss, signupPrivilege, dataExposure];

export function resolveChecks(names: string[], options: Record<string, unknown> = {}): Check[] {
  if (names.length === 0) {
    // Default: every read-only check. An active check (it writes) joins only
    // when it is named, or when its own options say enabled: true; the scope
    // still refuses it unless allowActiveTesting is on.
    return REGISTRY.filter((c) => c.readOnly || (options[c.name] as { enabled?: unknown } | undefined)?.enabled === true);
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
