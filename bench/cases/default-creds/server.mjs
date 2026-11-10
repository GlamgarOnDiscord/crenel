// A login endpoint (POST /login only) where `weak@x` uses the well-known password
// "admin123" and rejects anything else (control holds); `strong@x` rejects every
// dictionary password (decoy); `open@x` accepts ANY password with a real token
// (accept-all) — the negative control must keep it UNPROVEN, or the check would
// false-positive on a broken endpoint.
import { createServer } from "node:http";
const token = () => '{"authentication":{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.ZmFrZXNpZ25hdHVyZXZhbHVl"}}';
export default () => createServer((req, res) => {
  if (req.method !== "POST" || new URL(req.url ?? "/", "http://x").pathname !== "/login") { res.writeHead(404); return res.end("no"); }
  let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    let email = "", password = ""; try { ({ email, password } = JSON.parse(b)); } catch {}
    if (email === "open@x") { res.writeHead(200, { "content-type": "application/json" }); return res.end(token()); } // accept-all
    if (email === "weak@x" && password === "admin123") { res.writeHead(200, { "content-type": "application/json" }); return res.end(token()); }
    res.writeHead(401); res.end('{"error":"invalid"}');
  });
});
