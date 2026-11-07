// Auth middleware that rejects wrong tokens but lets requests WITHOUT a token
// through: account A gets 403 on B's export, an anonymous caller gets it all.
import { json, serve, USERS } from "../../lib/tenant-app.mjs";

const exportsById = { exp_b_1: { id: "exp_b_1", tenant: "t_b", csv: "email,plan\nb@example.com,pro" } };

export default () => serve([
  { pattern: /^\/api\/exports\/([^/]+)$/, handle(req, res, id) {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
    const e = exportsById[id]; if (!e) return json(res, 404, { error: "not found" });
    if (m) { // BUG: only checks tenancy when a token is present
      const u = USERS[m[1]]; if (!u) return json(res, 401, { error: "auth" });
      if (u.tenant !== e.tenant) return json(res, 403, { error: "forbidden" });
    }
    return json(res, 200, e);
  } },
]);
