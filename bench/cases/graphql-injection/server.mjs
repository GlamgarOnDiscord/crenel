// A minimal GraphQL-ish endpoint: it answers introspection and the probe queries
// the check sends, without a real GraphQL engine. vulnSearch(q) is boolean-SQLi
// (a TRUE tautology returns rows); runCmd(c) is command-injectable (evaluates
// 7*7); safeSearch(q) treats q as a literal (the decoy).
import { createServer } from "node:http";

const SCHEMA = { data: { __schema: {
  queryType: { fields: [
    { name: "safeSearch", args: [{ name: "q", type: { kind: "SCALAR", name: "String", ofType: null } }], type: { kind: "LIST", name: null, ofType: { kind: "OBJECT", name: "Row", ofType: null } } },
    { name: "vulnSearch", args: [{ name: "q", type: { kind: "SCALAR", name: "String", ofType: null } }], type: { kind: "LIST", name: null, ofType: { kind: "OBJECT", name: "Row", ofType: null } } },
    { name: "runCmd", args: [{ name: "c", type: { kind: "SCALAR", name: "String", ofType: null } }], type: { kind: "SCALAR", name: "String", ofType: null } },
  ] },
  mutationType: { fields: [] },
} } };
const ROWTYPE = { data: { __type: { fields: [{ name: "id", type: { kind: "SCALAR", name: "ID", ofType: null } }] } } };

const read = (req) => new Promise((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
export default () => createServer(async (req, res) => {
  const body = await read(req);
  let q = ""; try { q = JSON.parse(body).query ?? ""; } catch {}
  const send = (o) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  if (/__schema/.test(q)) return send(SCHEMA);
  if (/__type\(name:\s*"Row"\)/.test(q)) return send(ROWTYPE);
  const call = /(\w+)\(\s*\w+:\s*"((?:[^"\\]|\\.)*)"/.exec(q);
  if (!call) return send({ data: {} });
  const field = call[1], arg = call[2].replace(/\\"/g, '"');
  if (field === "runCmd") {
    const m = arg.match(/echo\s+(\S*?)\$\(\(7\*7\)\)/); // shell evaluates the arithmetic
    return send({ data: { runCmd: m ? m[1] + "49" : "" } });
  }
  if (field === "vulnSearch") {
    const rows = /'\s*OR\s*'1'='1/i.test(arg) ? [{ id: "1" }, { id: "2" }, { id: "3" }] : []; // tautology -> all rows
    return send({ data: { vulnSearch: rows } });
  }
  // safeSearch: q is a literal; it never matches the probe strings -> always []
  return send({ data: { safeSearch: [] } });
});
