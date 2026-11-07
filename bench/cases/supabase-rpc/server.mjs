// A fake Supabase gateway + PostgREST for three functions. GET runs in a
// read-only transaction, as PostgREST does: a function that writes answers 405.
import { readFileSync } from "node:fs";
import { json, serve } from "../../lib/tenant-app.mjs";

const ANON = readFileSync(new URL("./anon.txt", import.meta.url), "utf8").trim();
const fns = {
  search_members: () => [200, [{ id: 1, display_name: "Bea", email: "bea@example.com" }, { id: 2, display_name: "Ali", email: "ali@example.com" }]],
  my_invoices: () => [200, []],
  track_view: () => [405, { code: "25006", message: "cannot execute INSERT in a read-only transaction" }],
};

export default () => serve([
  { pattern: /^\/rest\/v1\/rpc\/([a-z_]+)$/, handle(req, res, name) {
    if (req.headers.apikey !== ANON) return json(res, 401, { message: "No API key found in request" });
    const f = fns[name];
    if (!f) return json(res, 404, { code: "PGRST202", message: "Could not find the function" });
    const [s, b] = f();
    json(res, s, b);
  } },
]);
