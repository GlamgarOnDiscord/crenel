// A Next.js app whose next.config has images.remotePatterns: [{ hostname: "**" }].
// The optimizer is simulated: it answers as Next does after fetching a page
// that is not an image, without ever fetching anything itself.
import { createServer } from "node:http";

export default () => createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  if (u.pathname !== "/_next/image") { res.writeHead(200, { "content-type": "text/html" }); return res.end("<!doctype html><div id=__next></div>"); }
  const url = u.searchParams.get("url");
  res.writeHead(400, { "content-type": "text/plain" });
  if (!url) return res.end('"url" parameter is required');
  if (![16, 32, 48, 64, 96, 128, 256, 384, 640, 750, 828, 1080].includes(Number(u.searchParams.get("w")))) return res.end(`"w" parameter (width) of ${u.searchParams.get("w")} is not allowed`);
  res.end("The requested resource isn't a valid image.");
});
