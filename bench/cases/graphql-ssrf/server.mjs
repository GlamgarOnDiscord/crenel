// A GraphQL-ish endpoint: fetchUrl(url) fetches the URL server-side (SSRF);
// echo(text) does not (decoy). Answers the introspection the check sends.
import { createServer } from "node:http";
const SCHEMA = { data: { __schema: {
  queryType: { fields: [
    { name: "fetchUrl", args: [{ name: "url", type: { kind: "SCALAR", name: "String", ofType: null } }], type: { kind: "SCALAR", name: "String", ofType: null } },
    { name: "echo", args: [{ name: "text", type: { kind: "SCALAR", name: "String", ofType: null } }], type: { kind: "SCALAR", name: "String", ofType: null } },
  ] }, mutationType: { fields: [] },
} } };
const read = (req) => new Promise((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
export default () => createServer(async (req, res) => {
  let q = ""; try { q = JSON.parse(await read(req)).query ?? ""; } catch {}
  const send = (o) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  if (/__schema/.test(q)) return send(SCHEMA);
  const m = /fetchUrl\(\s*url:\s*"((?:[^"\\]|\\.)*)"/.exec(q);
  if (m) { try { await fetch(m[1].replace(/\\"/g, '"')); } catch {} return send({ data: { fetchUrl: "ok" } }); }
  return send({ data: { echo: "ok" } }); // echo never fetches
});
