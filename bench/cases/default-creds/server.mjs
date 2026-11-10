// A login endpoint where `weak@x` uses the well-known password "admin123" and
// rejects anything else (control holds); `strong@x` rejects every dictionary
// password (decoy). No accept-all path, so a proven finding means a real default
// credential, not a server that accepts everything.
import { createServer } from "node:http";
export default () => createServer((req, res) => {
  let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    let email = "", password = ""; try { ({ email, password } = JSON.parse(b)); } catch {}
    if (email === "weak@x" && password === "admin123") { res.writeHead(200, { "content-type": "application/json" }); return res.end('{"authentication":{"token":"t"}}'); }
    res.writeHead(401); res.end('{"error":"invalid"}');
  });
});
