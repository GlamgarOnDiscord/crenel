// /package.json.bak is served and pins a vulnerable lodash; /safe/package.json
// pins only patched versions (decoy).
import { createServer } from "node:http";
const VULN = JSON.stringify({ name: "app", dependencies: { lodash: "^4.17.4", express: "^4.17.3" } });
const SAFE = JSON.stringify({ name: "app", dependencies: { lodash: "^4.17.21", express: "^4.18.2" } });
export default () => createServer((req, res) => {
  const p = (req.url ?? "/").split("?")[0];
  const send = (b) => { res.writeHead(200, { "content-type": "application/json" }); res.end(b); };
  if (p === "/package.json.bak") return send(VULN);
  if (p === "/safe/package.json") return send(SAFE);
  res.writeHead(404); res.end("no");
});
