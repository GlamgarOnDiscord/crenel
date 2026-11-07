// One leaking route, one correct route, one soft-404 decoy.
import { json, serve, userOf } from "../../lib/tenant-app.mjs";

const projects = { proj_a_1: { id: "proj_a_1", tenant: "t_a", name: "Alpha" }, proj_b_1: { id: "proj_b_1", tenant: "t_b", name: "Bravo secret roadmap" } };
const invoices = { inv_a_1: { id: "inv_a_1", tenant: "t_a", total: 120 }, inv_b_1: { id: "inv_b_1", tenant: "t_b", total: 990 } };
const files = { file_a_1: { id: "file_a_1", tenant: "t_a" }, file_b_1: { id: "file_b_1", tenant: "t_b" } };

export default () => serve([
  // BUG: authenticated, but never checks the tenant.
  { pattern: /^\/api\/projects\/([^/]+)$/, handle(req, res, id) {
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    const p = projects[id]; return p ? json(res, 200, p) : json(res, 404, { error: "not found" });
  } },
  // Correct: foreign objects look like missing ones.
  { pattern: /^\/api\/invoices\/([^/]+)$/, handle(req, res, id) {
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    const i = invoices[id]; return i && i.tenant === u.tenant ? json(res, 200, i) : json(res, 404, { error: "not found" });
  } },
  // Correct but answers 200 with an error body (a soft 404): a status-only oracle calls it a leak.
  { pattern: /^\/api\/files\/([^/]+)$/, handle(req, res, id) {
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    const f = files[id]; return f && f.tenant === u.tenant ? json(res, 200, f) : json(res, 200, { ok: false, error: "Not found" });
  } },
]);
