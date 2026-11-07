// A fake Supabase REST endpoint (PostgREST shape). `profiles` has RLS off:
// the anon key reads every row. `orders` has RLS on: anon gets an empty list.
import { readFileSync } from "node:fs";
import { json, serve } from "../../lib/tenant-app.mjs";

const ANON = readFileSync(new URL("./anon.txt", import.meta.url), "utf8").trim();
const anonOk = (req) => req.headers.apikey === ANON || req.headers.authorization === `Bearer ${ANON}`;
const tables = {
  profiles: [{ id: 1, email: "b@example.com", phone: "+33600000000", plan: "pro" }],
  orders: [],
};

export default () => serve([
  { pattern: /^\/rest\/v1\/?()$/, handle(req, res) {
    if (!anonOk(req)) return json(res, 401, { message: "No API key found" });
    json(res, 200, { swagger: "2.0", paths: { "/profiles": {}, "/orders": {} }, definitions: { profiles: {}, orders: {} } });
  } },
  { pattern: /^\/rest\/v1\/([a-z_]+)$/, handle(req, res, table) {
    if (!anonOk(req)) return json(res, 401, { message: "No API key found" });
    if (!(table in tables)) return json(res, 404, { message: "relation does not exist" });
    json(res, 200, tables[table].slice(0, 1));
  } },
]);
