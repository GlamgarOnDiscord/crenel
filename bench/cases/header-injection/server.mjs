// /vuln copies the `next` param into a Location header without stripping CRLF, so
// extra headers in the value land in the response. /safe strips CR/LF (decoy).
import { createServer } from "node:http";
export default () => createServer((req, res) => {
  const u = new URL(req.url ?? "/", "http://x");
  const path = u.pathname, raw = decodeURIComponent(u.searchParams.get("next") ?? "");
  if (path === "/vuln") {
    // vulnerable: build the raw header block including the attacker's CRLF content
    const extra = raw.includes("\r\n") ? raw.split("\r\n").slice(1).join("\r\n") + "\r\n" : "";
    res.socket.write(`HTTP/1.1 302 Found\r\nLocation: ${raw.split("\r\n")[0]}\r\n${extra}Content-Length: 0\r\n\r\n`);
    return res.socket.end();
  }
  if (path === "/safe") { res.writeHead(302, { location: raw.replace(/[\r\n]/g, "") }); return res.end(); }
  res.writeHead(404); res.end("no");
});
