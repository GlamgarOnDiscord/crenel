// Profile and workspace updates: one copies the request body into the row, one
// lets the nested billing object through, one allowlists the fields a user may
// change, one validates with a strict schema (unknown field: 400).
import { json, serve, userOf } from "../../lib/tenant-app.mjs";

export default () => {
  const profiles = { user_a: { id: "user_a", name: "Ann", role: "member", credits: 10 } };
  const workspaces = { ws_a: { id: "ws_a", title: "A's space", billing: { plan: "free", seats: 1 } } };
  const accounts = { user_a: { id: "user_a", name: "Ann", isAdmin: false, plan: "free" } };
  const settings = { user_a: { id: "user_a", locale: "en", role: "member" } };
  const body = (req) => new Promise((r) => { let s = ""; req.on("data", (d) => (s += d)); req.on("end", () => { try { r(JSON.parse(s || "{}")); } catch { r({}); } }); });
  const me = (req, res) => { const u = userOf(req); if (!u) { json(res, 401, { error: "auth" }); return null; } return u; };
  return serve([
    { pattern: /^\/api\/me$/, handle(req, res) { const u = me(req, res); if (u) json(res, 200, profiles[u.id] ?? {}); } },
    // BUG: Object.assign(row, req.body).
    { method: "PATCH", pattern: /^\/api\/me$/, async handle(req, res) { const u = me(req, res); if (!u) return; Object.assign(profiles[u.id] ??= { id: u.id }, await body(req)); json(res, 200, profiles[u.id]); } },
    { pattern: /^\/api\/workspaces\/([^/]+)$/, handle(req, res, id) { const u = me(req, res); if (u) json(res, 200, workspaces[id] ?? {}); } },
    // BUG: the title is checked, but a nested billing object is merged as sent.
    { method: "PATCH", pattern: /^\/api\/workspaces\/([^/]+)$/, async handle(req, res, id) {
      const u = me(req, res); if (!u) return; const w = workspaces[id]; const b = await body(req);
      if (typeof b.title === "string") w.title = b.title;
      if (b.billing) w.billing = { ...w.billing, ...b.billing };
      json(res, 200, w);
    } },
    { pattern: /^\/api\/account$/, handle(req, res) { const u = me(req, res); if (u) json(res, 200, accounts[u.id] ?? {}); } },
    // Correct: only the fields a user may change are copied.
    { method: "PATCH", pattern: /^\/api\/account$/, async handle(req, res) {
      const u = me(req, res); if (!u) return; const b = await body(req); const a = accounts[u.id];
      if (typeof b.name === "string") a.name = b.name;
      json(res, 200, a);
    } },
    { pattern: /^\/api\/settings$/, handle(req, res) { const u = me(req, res); if (u) json(res, 200, settings[u.id] ?? {}); } },
    // Correct: a strict schema, unknown fields are a 400.
    { method: "PUT", pattern: /^\/api\/settings$/, async handle(req, res) {
      const u = me(req, res); if (!u) return; const b = await body(req); const s = settings[u.id];
      if (Object.keys(b).some((k) => !["id", "locale", "role"].includes(k)) || (b.role !== undefined && b.role !== s.role)) return json(res, 400, { error: "invalid fields" });
      if (typeof b.locale === "string") s.locale = b.locale;
      json(res, 200, s);
    } },
  ]);
};
