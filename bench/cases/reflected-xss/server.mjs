// /echo reflects q unescaped into HTML (vuln); /safe HTML-escapes it (decoy).
import { createServer } from "node:http";
const esc = (s) => s.replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]));
export default () => createServer((req, res) => {
  const u = new URL(req.url ?? "/", "http://x");
  const q = u.searchParams.get("q") ?? "";
  const html = (body) => { res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end(`<html><body>${body}</body></html>`); };
  if (u.pathname === "/echo") return html(`You searched: ${q}`);        // unescaped
  if (u.pathname === "/safe") return html(`You searched: ${esc(q)}`);   // escaped
  res.writeHead(404); res.end("no");
});
