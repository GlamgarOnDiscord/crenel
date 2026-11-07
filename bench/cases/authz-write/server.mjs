// Cross-tenant writes: a PATCH and a DELETE that never check the owner, a PATCH
// that does, and a PATCH that answers 200 to anyone but only changes the
// caller's own objects (a status-only tool calls it a leak).
import { json, serve, userOf } from "../../lib/tenant-app.mjs";

const projects = { proj_a_1: { id: "proj_a_1", tenant: "t_a", name: "Alpha" }, proj_b_1: { id: "proj_b_1", tenant: "t_b", name: "Bravo" } };
const invoices = { inv_a_1: { id: "inv_a_1", tenant: "t_a", memo: "a" }, inv_b_1: { id: "inv_b_1", tenant: "t_b", memo: "b" } };
const settings = { set_a_1: { id: "set_a_1", tenant: "t_a", theme: "dark" }, set_b_1: { id: "set_b_1", tenant: "t_b", theme: "light" } };
const drafts = { draft_a_tmp: { id: "draft_a_tmp", tenant: "t_a" }, draft_b_tmp: { id: "draft_b_tmp", tenant: "t_b" } };

const body = (req) => new Promise((r) => { let s = ""; req.on("data", (d) => (s += d)); req.on("end", () => { try { r(JSON.parse(s || "{}")); } catch { r({}); } }); });
const read = (table) => (req, res, id) => {
  const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
  const o = table[id]; return o && o.tenant === u.tenant ? json(res, 200, o) : json(res, 404, { error: "not found" });
};

export default () => serve([
  { pattern: /^\/api\/projects\/([^/]+)$/, handle: read(projects) },
  // BUG: signed in is enough to rename anyone's project.
  { method: "PATCH", pattern: /^\/api\/projects\/([^/]+)$/, async handle(req, res, id) {
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    const p = projects[id]; if (!p) return json(res, 404, { error: "not found" });
    const b = await body(req); if (typeof b.name === "string") p.name = b.name;
    return json(res, 200, p);
  } },
  { pattern: /^\/api\/invoices\/([^/]+)$/, handle: read(invoices) },
  // Correct: the update is scoped to the caller's tenant.
  { method: "PATCH", pattern: /^\/api\/invoices\/([^/]+)$/, async handle(req, res, id) {
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    const i = invoices[id]; if (!i || i.tenant !== u.tenant) return json(res, 404, { error: "not found" });
    const b = await body(req); if (typeof b.memo === "string") i.memo = b.memo;
    return json(res, 200, i);
  } },
  { pattern: /^\/api\/settings\/([^/]+)$/, handle: read(settings) },
  // Correct, but answers 200 {ok:true} even when nothing matched (update ... where tenant = ?).
  { method: "PATCH", pattern: /^\/api\/settings\/([^/]+)$/, async handle(req, res, id) {
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    const s = settings[id]; const b = await body(req);
    if (s && s.tenant === u.tenant && typeof b.theme === "string") s.theme = b.theme;
    return json(res, 200, { ok: true });
  } },
  { pattern: /^\/api\/drafts\/([^/]+)$/, handle: read(drafts) },
  // BUG: delete by id, no owner check.
  { method: "DELETE", pattern: /^\/api\/drafts\/([^/]+)$/, handle(req, res, id) {
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    if (!drafts[id]) return json(res, 404, { error: "not found" });
    delete drafts[id]; return json(res, 204, {});
  } },
]);
