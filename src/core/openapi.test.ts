import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resourcesFromOpenApi } from "./openapi.js";
import { loadConfig } from "./config.js";

const spec = {
  openapi: "3.0.0",
  servers: [{ url: "https://api.example.com/v1" }],
  paths: {
    "/projects/{projectId}": { get: {}, delete: {} },
    "/orgs/{orgId}/members/{memberId}": { get: {} },
    "/projects": { get: {} },
    "/invoices/{id}": { post: {} },
    "/status/{region}": { get: { security: [] } },
  },
};

test("imports GET routes with one path parameter, with the server prefix; public ones are marked", () => {
  assert.deepEqual(resourcesFromOpenApi(spec), [
    { name: "projects", path: "/v1/projects/:id", methods: ["GET"] },
    { name: "status", path: "/v1/status/:id", methods: ["GET"], public: true },
  ]);
});

test("loadConfig merges the imported routes; a declared resource of the same name wins", () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-openapi-"));
  try {
    writeFileSync(join(dir, "api.json"), JSON.stringify(spec));
    writeFileSync(join(dir, "crenel.config.yaml"), [
      "projectDir: .",
      "scope: { allowedHosts: [api.example.com] }",
      "options:",
      "  authz-matrix:",
      "    openapi: api.json",
      "    resources:",
      "      - { name: projects, path: /v1/projects/:id, methods: [GET] }",
      "    accounts: { b: { owns: { projects: [p1] } } }",
    ].join("\n"));
    const cfg = loadConfig(join(dir, "crenel.config.yaml"));
    const names = ((cfg.options["authz-matrix"] as { resources: { name: string }[] }).resources).map((r) => r.name);
    assert.deepEqual(names, ["projects", "status"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
