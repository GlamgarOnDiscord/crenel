import { createServer } from "node:http";

export default () => createServer((req, res) => {
  const u = new URL(req.url ?? "/", "http://x");
  const target = u.searchParams.get("to");
  if (u.pathname === "/redirect" && target) { res.writeHead(302, { location: target }); return res.end(); }
  if (u.pathname === "/fixed" && target) { res.writeHead(302, { location: "/home" }); return res.end(); }
  res.writeHead(200); res.end("ok");
});
