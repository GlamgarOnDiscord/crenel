// Three distinct mechanisms share one realistic API. Each real flaw has a
// sibling that is correctly gated plus a public/ignored control. This makes
// status-only, reflection-only and accept-all oracles fail the case.
import { json, serve, userOf } from "../../lib/tenant-app.mjs";

const auth = (req) => String(req.headers.authorization ?? "");
const USERS = { data: [{ id: "user-a", email: "a@example.test" }, { id: "user-b", email: "b@example.test" }] };

export default () => serve([
  // BUG: the organization is present, but the project leaf is returned to any
  // authenticated tenant. The random non-existent-leaf control still 404s.
  { pattern: /^\/api\/orgs\/org-b\/projects\/([^/]+)$/, handle(req, res, id) {
    if (!userOf(req)) return json(res, 401, { error: "auth required" });
    if (id !== "project-b") return json(res, 404, { error: "project not found" });
    return json(res, 200, { id, org: "org-b", owner: "owner-b@example.test", title: "Confidential migration" });
  } },
  // Correct: both the organization and invoice leaf belong to B.
  { pattern: /^\/api\/orgs\/org-b\/invoices\/([^/]+)$/, handle(req, res, id) {
    const user = userOf(req);
    if (!user) return json(res, 401, { error: "auth required" });
    if (id !== "invoice-b") return json(res, 404, { error: "invoice not found" });
    if (user.tenant !== "t_b") return json(res, 403, { error: "forbidden" });
    return json(res, 200, { id, org: "org-b", total: 8400 });
  } },
  // Public by design: the anonymous control prevents a BOLA proof.
  { pattern: /^\/api\/orgs\/org-b\/notes\/([^/]+)$/, handle(_req, res, id) {
    return id === "note-b" ? json(res, 200, { id, visibility: "public" }) : json(res, 404, { error: "note not found" });
  } },

  // BUG: login is enforced, role is not. Admin and member receive the same view.
  { pattern: /^\/api\/admin\/users$/, handle(req, res) {
    if (!auth(req)) return json(res, 401, { error: "auth required" });
    return json(res, 200, USERS);
  } },
  // Correct administrator gate.
  { pattern: /^\/api\/admin\/audit$/, handle(req, res) {
    const value = auth(req);
    if (!value) return json(res, 401, { error: "auth required" });
    if (value !== "Bearer admin-token") return json(res, 403, { error: "admin required" });
    return json(res, 200, { events: [{ action: "login", actor: "user-a" }] });
  } },
  // Public by design; there is no privileged function to bypass.
  { pattern: /^\/api\/stats$/, handle(_req, res) { return json(res, 200, { users: 2, status: "ok" }); } },

  // BUG: name is concatenated into a lookup. Evaluate a generic equality in
  // the injected boolean suffix rather than recognizing one tool's payloads:
  // 1=1, 2=2 and quoted/string equivalents all behave as tautologies.
  { pattern: /^\/api\/lookup\/([^/]+)$/, handle(_req, res, name) {
    const expression = /\b(OR|AND)\s+\(?\s*["']?([A-Za-z0-9_.-]+)["']?\s*=\s*["']?([A-Za-z0-9_.-]+)["']?/i.exec(name);
    const truthy = expression?.[1].toUpperCase() === "OR" && expression[2] === expression[3];
    const falsy = expression?.[1].toUpperCase() === "AND" && expression[2] !== expression[3];
    if (falsy) return json(res, 404, { error: "not found" });
    if (name === "alice" || truthy) return json(res, 200, { username: "alice", role: "member" });
    return json(res, 404, { error: "not found" });
  } },
  // Correct literal search: probes are just values that do not exist.
  { pattern: /^\/api\/search$/, handle(req, res) {
    const q = new URL(req.url, "http://local").searchParams.get("q");
    return q === "alice" ? json(res, 200, { username: "alice" }) : json(res, 404, { error: "not found" });
  } },
  // Correct stable catalog: sort is allowlisted and unrecognized values fall
  // back to name. An ignored input must not look injectable.
  { pattern: /^\/api\/catalog$/, handle(_req, res) { return json(res, 200, { items: [{ id: 1, name: "A" }] }); } },
]);
