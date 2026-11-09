// /vuln echoes any Origin into ACAO with credentials (exploitable). /safe echoes
// the Origin but without credentials (not exploitable) — the decoy.
import { createServer } from "node:http";
export default () => createServer((req, res) => {
  const origin = req.headers.origin ?? "";
  const url = (req.url ?? "/").split("?")[0];
  if (url === "/vuln") {
    res.writeHead(200, { "content-type": "application/json", "access-control-allow-origin": origin, "access-control-allow-credentials": "true" });
    return res.end('{"user":"alice","balance":4200}');
  }
  if (url === "/safe") {
    res.writeHead(200, { "content-type": "application/json", "access-control-allow-origin": origin }); // reflected, but NO credentials
    return res.end('{"ok":true}');
  }
  res.writeHead(404); res.end("no");
});
