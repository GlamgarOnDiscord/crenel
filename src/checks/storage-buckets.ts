// storage-buckets: cloud storage the client code points at (S3, R2, GCS,
// Supabase Storage, Firebase Storage). Uploads and exports often land in a
// bucket left listable: anyone can enumerate every user's files. Static: the
// bucket URLs in the scanned code are listed as leads. Live (the bucket host is
// declared in scope.allowedHosts): one GET on the bucket root; an XML/JSON
// object listing is the proof. Nothing is downloaded beyond that listing page.

import { readFileSync, statSync } from "node:fs";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, extOf, relative } from "../core/walk.js";
import { safeFetch } from "../core/net.js";

const SCAN = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".json", ".env"]);
const BUCKET_URL = /https:\/\/(?:[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com|s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]|[a-z0-9-]+\.r2\.dev|pub-[a-f0-9]{32}\.r2\.dev|storage\.googleapis\.com\/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]|[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]\.storage\.googleapis\.com)/gi;
const LISTING = /<ListBucketResult|<EnumerationResults|"kind"\s*:\s*"storage#objects"/;

export function bucketUrls(text: string): string[] {
  return [...new Set([...text.matchAll(BUCKET_URL)].map((m) => m[0].replace(/\/+$/, "")))];
}

export const storageBuckets: Check = {
  name: "storage-buckets",
  title: "Cloud storage buckets referenced by the app, and whether anyone can list them",
  readOnly: true, // static scan, plus one GET per declared bucket host
  async run(ctx: CheckContext): Promise<Finding[]> {
    const where = new Map<string, string>();
    for (const file of walkFiles(ctx.projectDir, { accept: (n) => SCAN.has(extOf(n)) || n.startsWith(".env") })) {
      let text: string;
      try { if (statSync(file).size > 4 * 1024 * 1024) continue; text = readFileSync(file, "utf8"); } catch { continue; }
      for (const u of bucketUrls(text)) if (!where.has(u)) where.set(u, relative(ctx.projectDir, file) || file);
    }
    const findings: Finding[] = [];
    for (const [bucket, file] of where) {
      // GCS path-style buckets list at the JSON API; S3/R2 virtual-host buckets at the root.
      const listUrl = /storage\.googleapis\.com\/([^/]+)$/.test(bucket)
        ? `https://storage.googleapis.com/storage/v1/b/${bucket.split("/").pop()}/o?maxResults=1`
        : `${bucket}/?max-keys=1`;
      if (ctx.scope.isHostAllowed(listUrl)) {
        try {
          const res = await safeFetch(listUrl, ctx.scope);
          if (res.status === 200 && LISTING.test(res.body)) {
            findings.push({
              id: `storage-buckets:listable:${bucket}`, check: "storage-buckets",
              title: `Bucket ${bucket} can be listed by anyone`, severity: "high", state: "proven", location: bucket,
              description: `${bucket} (referenced in ${file}) answers an anonymous listing request with its object index: anyone can enumerate and download every file in it, user uploads included.`,
              remediation: "Turn off public listing (block public access on S3, no public bucket on R2/GCS), serve files through signed URLs, and keep uploads private by default.",
              proof: { method: "one anonymous GET on the bucket listing endpoint (first key only)", replay: `curl -s '${listUrl}' | head -c 400`, evidence: `HTTP 200, object listing returned` },
              regressionHint: `${listUrl} must not return a listing without credentials.`,
            });
            continue;
          }
        } catch (err) { ctx.log(`storage-buckets: ${listUrl}: ${(err as Error).message}`); }
      }
      findings.push({
        id: `storage-buckets:referenced:${bucket}`, check: "storage-buckets",
        title: `Storage bucket referenced by the app: ${bucket}`, severity: "low", state: "unproven", location: `${file}`,
        description: `The code points at ${bucket}. If it holds user files, it must not be listable or readable without a signed URL.`,
        remediation: `Declare ${new URL(listUrl).hostname} in scope.allowedHosts to let Crenel check whether it can be listed anonymously.`,
        proof: { method: "bucket URL found in the scanned code", replay: `grep -rn '${new URL(bucket).hostname}' '${file}'` },
      });
    }
    ctx.log(`storage-buckets: ${where.size} bucket(s), ${findings.filter((f) => f.state === "proven").length} listable`);
    return findings;
  },
};
