import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bucketUrls, storageBuckets } from "./storage-buckets.js";
import { Scope } from "../core/scope.js";

test("finds S3, R2 and GCS bucket URLs, not ordinary hosts", () => {
  const text = 'a="https://acme-uploads.s3.eu-west-3.amazonaws.com/u/1.png" b="https://pub-0123456789abcdef0123456789abcdef.r2.dev/x" c="https://storage.googleapis.com/acme-exports/a.csv" d="https://cdn.acme.com/x.png"';
  assert.deepEqual(bucketUrls(text).sort(), [
    "https://acme-uploads.s3.eu-west-3.amazonaws.com",
    "https://pub-0123456789abcdef0123456789abcdef.r2.dev",
    "https://storage.googleapis.com/acme-exports",
  ]);
});

test("an undeclared bucket host is a lead and is never requested", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-bucket-"));
  writeFileSync(join(dir, "app.js"), 'fetch("https://acme-uploads.s3.amazonaws.com/avatars/1.png")\n');
  try {
    const found = await storageBuckets.run({ scope: new Scope({ allowedHosts: [] }), projectDir: dir, options: {}, log: () => {} });
    assert.equal(found.length, 1);
    assert.equal(found[0]!.state, "unproven");
    assert.match(found[0]!.remediation, /acme-uploads\.s3\.amazonaws\.com/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
