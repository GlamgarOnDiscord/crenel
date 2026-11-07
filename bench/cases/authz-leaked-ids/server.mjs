// B's project lists its attachment ids. One attachment route forgets the owner
// check, but only for some objects; nobody declared those ids in the config.
import { json, serve, userOf } from "../../lib/tenant-app.mjs";

const projects = { proj_b_1: { id: "proj_b_1", tenant: "t_b", attachments: ["att_b_7", "att_pub_1", "att_b_8"] } };
const attachments = {
  att_b_7: { id: "att_b_7", tenant: "t_b", file: "contract-signed.pdf", leaky: true },
  att_b_8: { id: "att_b_8", tenant: "t_b", file: "payroll.csv" },
  att_pub_1: { id: "att_pub_1", tenant: "t_b", file: "logo.png", public: true },
};

export default () => serve([
  { pattern: /^\/api\/projects\/([^/]+)$/, handle(req, res, id) {
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    const p = projects[id]; return p && p.tenant === u.tenant ? json(res, 200, p) : json(res, 404, { error: "not found" });
  } },
  { pattern: /^\/api\/attachments\/([^/]+)$/, handle(req, res, id) {
    const a = attachments[id]; if (!a) return json(res, 404, { error: "not found" });
    if (a.public) return json(res, 200, a);
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    if (!a.leaky && a.tenant !== u.tenant) return json(res, 404, { error: "not found" }); // BUG: leaky rows skip it
    return json(res, 200, a);
  } },
]);
