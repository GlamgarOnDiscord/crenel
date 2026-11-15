import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverSourceRoutes } from "./source-routes.js";

test("source route reconnaissance covers common frameworks, deduplicates, and ignores prose", () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-source-routes-"));
  try {
    writeFileSync(join(dir, "api.ts"), [
      'router.get("/api/projects/:id", handler);',
      'app.post("/api/invites", createInvite);',
      'axios.patch("/api/profile", updateProfile);',
      'fetch("/api/jobs", { method: "POST", body: "{}" });',
      'router.get("/api/projects/:id", duplicate);',
      '// app.delete("/comment-only", handler);',
      'const documentation = "router.delete(\\\"/not-code\\\")";',
    ].join("\n"));
    writeFileSync(join(dir, "app.py"), [
      '@app.get("/users/{user_id}")',
      '@blueprint.route("/session", methods=["POST"])',
    ].join("\n"));
    writeFileSync(join(dir, "Users.java"), '@DeleteMapping(value = "/admin/users/{id}")\n');
    writeFileSync(join(dir, "routes.php"), "Route::patch('/account', 'AccountController@update');\n");
    writeFileSync(join(dir, "routes.rb"), "get '/reports/:id' do\n");
    writeFileSync(join(dir, "main.go"), 'http.HandleFunc(`/healthz`, health)\nr.PUT(`/orders/:id`, update)\n');
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules", "noise.js"), 'app.get("/dependency-noise", h)');
    assert.deepEqual(discoverSourceRoutes(dir).map(({ method, path }) => `${method} ${path}`).sort(), [
      "GET /api/projects/:id", "POST /api/invites", "GET /users/{user_id}", "POST /session",
      "DELETE /admin/users/{id}", "PATCH /account", "PATCH /api/profile", "POST /api/jobs", "GET /reports/:id", "ANY /healthz", "PUT /orders/:id",
    ].sort());
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("source route reconnaissance skips test and fixture source files", () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-source-noise-"));
  try {
    mkdirSync(join(dir, "fixtures"));
    writeFileSync(join(dir, "api.test.ts"), 'app.get("/test-only", h)');
    writeFileSync(join(dir, "fixtures", "server.ts"), 'app.get("/fixture-only", h)');
    writeFileSync(join(dir, "api.ts"), 'app.get("/production", h)');
    assert.deepEqual(discoverSourceRoutes(dir).map(({ path }) => path), ["/production"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("source route reconnaissance derives Next.js app and pages API routes from file layout", () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-source-next-"));
  try {
    const app = join(dir, "src", "app", "api", "teams", "[teamId]", "members", "route.ts");
    mkdirSync(join(app, ".."), { recursive: true });
    writeFileSync(app, "export async function GET() {}\nexport const POST = handler\n// export function DELETE() {}\n");
    const pages = join(dir, "pages", "api", "reports", "[...slug].ts");
    mkdirSync(join(pages, ".."), { recursive: true });
    writeFileSync(pages, "export default function handler() {}\n");
    assert.deepEqual(discoverSourceRoutes(dir).map(({ method, path }) => `${method} ${path}`).sort(), [
      "ANY /api/reports/:slug*", "GET /api/teams/:teamId/members", "POST /api/teams/:teamId/members",
    ]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("source route reconnaissance resolves prefixed router mounts", () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-source-mount-"));
  try {
    writeFileSync(join(dir, "server.ts"), [
      'const router = express.Router();',
      'router.get("/users/:id", h);',
      'api.post("/orders", h);',
      'app.get("/health", h);',
      'app.use("/api/v2", router);',
      'app.use("/api/v2", api);',
      'app.use(cors());',
      '// app.use("/ignored", router);',
    ].join("\n"));
    assert.deepEqual(discoverSourceRoutes(dir).map(({ method, path }) => `${method} ${path}`).sort(), [
      "GET /users/:id", "GET /api/v2/users/:id",
      "POST /orders", "POST /api/v2/orders",
      "GET /health",
    ].sort());
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("source route reconnaissance does not double a route already under its mount prefix", () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-source-mount-abs-"));
  try {
    writeFileSync(join(dir, "server.ts"), [
      'router.get("/api/users/:id", h);',
      'app.use("/api", router);',
    ].join("\n"));
    assert.deepEqual(discoverSourceRoutes(dir).map(({ method, path }) => `${method} ${path}`), ["GET /api/users/:id"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("source route reconnaissance is bounded", () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-source-routes-cap-"));
  try {
    writeFileSync(join(dir, "api.js"), Array.from({ length: 20 }, (_, i) => `app.get("/r/${i}", h)`).join("\n"));
    assert.equal(discoverSourceRoutes(dir, 3).length, 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
