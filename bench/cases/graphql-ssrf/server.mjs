// A GraphQL stand-in with a real SSRF sink. Introspection advertises a structured
// sink importUrl(host,port,path,scheme) that genuinely fetches host:port/path (so
// the check's out-of-band listener is hit), a destructive-named purgeByUrl(url)
// that must never be fired, and a safe echo(url) that never fetches (decoy).
import { createServer, get } from "node:http";
const S = { kind: "SCALAR", name: "String", ofType: null };
const I = { kind: "SCALAR", name: "Int", ofType: null };
const a = (name, t) => ({ name, type: t });
export default () => createServer((req, res) => {
  let body = ""; req.on("data", (c) => (body += c)); req.on("end", () => {
    let query = ""; try { query = JSON.parse(body).query ?? ""; } catch {}
    const send = (o) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
    if (query.includes("__schema")) return send({ data: { __schema: {
      queryType: { fields: [] },
      mutationType: { fields: [
        { name: "importUrl", args: [a("host", S), a("port", I), a("path", S), a("scheme", S)] },
        { name: "purgeByUrl", args: [a("url", S)] },
        { name: "echo", args: [a("url", S)] },
      ] },
    } } });
    const m = /importUrl\(host:\s*"([^"]+)",\s*port:\s*(\d+),\s*path:\s*"([^"]+)"/.exec(query);
    if (m) { get(`http://${m[1]}:${m[2]}${m[3]}`, (r) => r.resume()).on("error", () => {}); return send({ data: { importUrl: { __typename: "Imp" } } }); }
    if (query.includes("purgeByUrl")) return send({ errors: [{ message: "purgeByUrl must not be probed" }] });
    return send({ data: { echo: { __typename: "E" } } });
  });
});
