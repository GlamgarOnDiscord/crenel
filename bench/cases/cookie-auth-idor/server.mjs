// A session-cookie app (Flask-Login / Django / Rails style): identity is a
// session cookie, not a bearer token. The note route is login-gated but forgets
// the OWNERSHIP check, so ANY logged-in user reads any tenant's note. A caller
// with no cookie is redirected to the login page (302); a non-existent id is 404.
// This exercises authz-matrix's cookie/marker auth path, no bearer anywhere.
import { serve, json } from "../../lib/tenant-app.mjs";

const notes = {
  note_a_1: { id: "note_a_1", tenant: "t_a", body: "a private note" },
  note_b_1: { id: "note_b_1", tenant: "t_b", body: "contact b@tenant.example about the renewal" },
};

export default () => serve([
  { pattern: /^\/notes\/([^/]+)$/, handle(req, res, id) {
    const note = notes[id];
    if (!note) return json(res, 404, { error: "not found" });
    // login-gated, but no tenant/owner check once you are logged in: the bug.
    const loggedIn = /(?:^|;\s*)session=/.test(req.headers.cookie ?? "");
    if (!loggedIn) { res.writeHead(302, { location: "/login" }); return res.end(); }
    return json(res, 200, note);
  } },
]);
