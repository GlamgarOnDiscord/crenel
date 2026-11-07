// A Next.js app whose remotePatterns list only its own image CDN.
import { createServer } from "node:http";

export default () => createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  if (u.pathname !== "/_next/image") { res.writeHead(200, { "content-type": "text/html" }); return res.end("<!doctype html><div id=__next></div>"); }
  const url = u.searchParams.get("url");
  res.writeHead(400, { "content-type": "text/plain" });
  if (!url) return res.end('"url" parameter is required');
  let host = "";
  try { host = new URL(url, "http://local").hostname; } catch { return res.end('"url" parameter is invalid'); }
  if (host !== "images.acme-cdn.test" && host !== "local") return res.end('"url" parameter is not allowed');
  res.end("The requested resource isn't a valid image.");
});
