// The Lovable pattern (April 2026): the ownership fix only covers objects
// created after the migration. Legacy objects still leak.
import { json, serve, userOf } from "../../lib/tenant-app.mjs";

const projects = {
  proj_b_legacy: { id: "proj_b_legacy", tenant: "t_b", name: "Bravo 2025", legacy: true },
  proj_b_new: { id: "proj_b_new", tenant: "t_b", name: "Bravo 2026" },
};

export default () => serve([
  { pattern: /^\/api\/projects\/([^/]+)$/, handle(req, res, id) {
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    const p = projects[id]; if (!p) return json(res, 404, { error: "not found" });
    if (!p.legacy && p.tenant !== u.tenant) return json(res, 404, { error: "not found" }); // BUG: legacy rows skip the check
    return json(res, 200, p);
  } },
]);
