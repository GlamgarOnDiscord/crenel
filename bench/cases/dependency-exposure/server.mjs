// /package.json.bak is served and EXACTLY pins a vulnerable lodash/express;
// /safe/package.json exactly pins only patched versions (decoy). Exact pins
// matter: dependency-exposure proves only an exactly-pinned vulnerable version,
// never a range (a range's resolved version may be patched).
import { createServer } from "node:http";
const VULN = JSON.stringify({ name: "app", dependencies: { lodash: "4.17.4", express: "4.17.1" } });
const SAFE = JSON.stringify({ name: "app", dependencies: { lodash: "4.17.21", express: "4.18.2" } });
export default () => createServer((req, res) => {
  const p = (req.url ?? "/").split("?")[0];
  const send = (b) => { res.writeHead(200, { "content-type": "application/json" }); res.end(b); };
  if (p === "/safe/package.json") return send(SAFE);
  if (p === "/package.json.bak") return send(VULN);
  res.writeHead(404); res.end("no");
});
